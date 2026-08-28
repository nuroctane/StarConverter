//! Deterministic, read-only manifests for normalized filesystem graphs.
//!
//! The verifier hashes logical stream contents from a regular [`ImageFile`]. Sparse and
//! uninitialized ranges hash as zeroes, matching the bytes applications observe. Namespace paths
//! are retained as raw UTF-16, and hard links remain one object with multiple paths.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use sha2::{Digest, Sha256};

use crate::extent::{Extent, Placement, StreamId};
use crate::image::{BoundedImageReader, ImageError, ImageFile};
use crate::object::{
    ObjectGraph, ObjectId, ObjectKind, ObjectSemantics, StreamFlags, StreamStorage,
};

static ZEROES: [u8; 64 * 1024] = [0; 64 * 1024];
const MANIFEST_COMMITMENT_DOMAIN: &[u8] = b"starconverter/logical-manifest-commitment/v1\0";

/// Resource bounds for one manifest operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationLimits {
    pub max_objects: usize,
    pub max_paths: usize,
    pub max_streams: usize,
    pub max_total_logical_bytes: u64,
    pub read_chunk_bytes: usize,
}

impl Default for VerificationLimits {
    fn default() -> Self {
        Self {
            max_objects: 4 * 1024 * 1024,
            max_paths: 8 * 1024 * 1024,
            max_streams: 8 * 1024 * 1024,
            max_total_logical_bytes: 1_u64 << 50,
            read_chunk_bytes: 1024 * 1024,
        }
    }
}

/// One root-relative path represented as exact UTF-16 components.
pub type Utf16Path = Vec<Vec<u16>>;

/// Content evidence for one unnamed or named stream.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamManifest {
    pub name: Option<Vec<u16>>,
    pub logical_bytes: u64,
    pub initialized_bytes: u64,
    pub mapped_bytes: u64,
    pub allocated_bytes: u64,
    pub flags: StreamFlags,
    pub sha256: [u8; 32],
}

/// Path-independent evidence for one object and every hard-link path to it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObjectManifest {
    pub kind: ObjectKind,
    pub semantics: ObjectSemantics,
    pub paths: Vec<Utf16Path>,
    pub streams: Vec<StreamManifest>,
}

/// A deterministic structural and logical-content manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationManifest {
    pub objects: Vec<ObjectManifest>,
    pub metadata_sha256: [u8; 32],
    pub logical_bytes_hashed: u64,
}

impl VerificationManifest {
    /// Requires exact normalized metadata and logical content equality.
    #[must_use]
    pub fn equivalent_to(&self, other: &Self) -> bool {
        self.metadata_sha256 == other.metadata_sha256 && self.objects == other.objects
    }
}

/// Compact, versioned commitment to a complete logical verification manifest.
///
/// This is crate-private because possession is evidence, not caller-supplied input. The committed
/// metadata digest already covers every path, semantic flag, stream size, and logical content
/// hash; the explicit counts prevent a decoder from discarding the manifest's bounded-work facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManifestCommitment {
    digest: [u8; 32],
    logical_bytes_hashed: u64,
    object_count: u64,
}

impl ManifestCommitment {
    /// Commits to one fully built manifest using a domain-separated canonical encoding.
    pub(crate) fn from_manifest(
        manifest: &VerificationManifest,
    ) -> Result<Self, VerificationError> {
        let object_count = u64::try_from(manifest.objects.len()).map_err(|_| {
            VerificationError::ArithmeticOverflow {
                calculation: "manifest commitment object count",
            }
        })?;
        let mut hasher = Sha256::new();
        hasher.update(MANIFEST_COMMITMENT_DOMAIN);
        hasher.update(manifest.metadata_sha256);
        hasher.update(manifest.logical_bytes_hashed.to_le_bytes());
        hasher.update(object_count.to_le_bytes());
        Ok(Self {
            digest: hasher.finalize().into(),
            logical_bytes_hashed: manifest.logical_bytes_hashed,
            object_count,
        })
    }

    /// Recomputes the commitment instead of trusting separately supplied manifest fields.
    pub(crate) fn matches(
        self,
        manifest: &VerificationManifest,
    ) -> Result<bool, VerificationError> {
        Ok(self == Self::from_manifest(manifest)?)
    }

    pub(crate) const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub(crate) const fn logical_bytes_hashed(self) -> u64 {
        self.logical_bytes_hashed
    }

    pub(crate) const fn object_count(self) -> u64 {
        self.object_count
    }

    /// Reconstructs only after a durable decoder has validated the schema and all bounds.
    pub(crate) const fn from_validated_parts(
        digest: [u8; 32],
        logical_bytes_hashed: u64,
        object_count: u64,
    ) -> Self {
        Self {
            digest,
            logical_bytes_hashed,
            object_count,
        }
    }
}

/// A bounded manifest construction failure.
#[derive(Debug)]
pub enum VerificationError {
    InvalidLimit {
        field: &'static str,
    },
    ObjectLimitExceeded {
        actual: usize,
        maximum: usize,
    },
    PathLimitExceeded {
        maximum: usize,
    },
    StreamLimitExceeded {
        maximum: usize,
    },
    LogicalByteLimitExceeded {
        requested: u64,
        maximum: u64,
    },
    MissingObjectPath(ObjectId),
    MissingStreamExtents(StreamId),
    /// Raw physical bytes are not the logical byte sequence for an encoded nonresident stream.
    /// A format-aware decompressor/decryptor must be introduced before such a stream can be
    /// included in a logical-content manifest.
    ExtentStreamRequiresDecoding {
        stream: StreamId,
        compressed: bool,
        encrypted: bool,
    },
    ExtentCoverageGap {
        stream: StreamId,
        expected: u64,
        actual: u64,
    },
    ArithmeticOverflow {
        calculation: &'static str,
    },
    Image(ImageError),
}

impl fmt::Display for VerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit { field } => write!(formatter, "verification limit {field} is zero"),
            Self::ObjectLimitExceeded { actual, maximum } => {
                write!(
                    formatter,
                    "object count {actual} exceeds verification cap {maximum}"
                )
            }
            Self::PathLimitExceeded { maximum } => {
                write!(
                    formatter,
                    "namespace path count exceeds verification cap {maximum}"
                )
            }
            Self::StreamLimitExceeded { maximum } => {
                write!(formatter, "stream count exceeds verification cap {maximum}")
            }
            Self::LogicalByteLimitExceeded { requested, maximum } => write!(
                formatter,
                "logical hashing request {requested} bytes exceeds verification cap {maximum}"
            ),
            Self::MissingObjectPath(object) => {
                write!(formatter, "object {} has no root-relative path", object.0)
            }
            Self::MissingStreamExtents(stream) => {
                write!(formatter, "stream {} has no extent evidence", stream.0)
            }
            Self::ExtentStreamRequiresDecoding {
                stream,
                compressed,
                encrypted,
            } => write!(
                formatter,
                "extent-backed stream {} requires logical decoding (compressed: {compressed}, encrypted: {encrypted}); raw physical storage is not logical content",
                stream.0
            ),
            Self::ExtentCoverageGap {
                stream,
                expected,
                actual,
            } => write!(
                formatter,
                "stream {} expected logical byte {expected}, found {actual}",
                stream.0
            ),
            Self::ArithmeticOverflow { calculation } => {
                write!(formatter, "overflow while calculating {calculation}")
            }
            Self::Image(error) => write!(formatter, "image verification read failed: {error}"),
        }
    }
}

impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Image(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ImageError> for VerificationError {
    fn from(error: ImageError) -> Self {
        Self::Image(error)
    }
}

/// Hashes every logical stream and produces a path-stable manifest without writing the image.
///
/// # Errors
///
/// Returns [`VerificationError`] if a limit is invalid or exhausted, an extent-backed stream
/// requires format-aware decompression or decryption, namespace traversal cannot assign a path,
/// extent coverage is inconsistent, arithmetic overflows, or an image read fails.
pub fn build_manifest(
    image: &ImageFile,
    graph: &ObjectGraph,
    limits: VerificationLimits,
) -> Result<VerificationManifest, VerificationError> {
    build_manifest_with_reader(image, graph, limits)
}

/// Hashes every logical stream through one crate-owned bounded image view.
///
/// This keeps the public regular-file API unchanged while allowing internal verification to hash
/// the bytes selected by a validated immutable overlay rather than accidentally reading its base
/// file directly.
pub(crate) fn build_manifest_with_reader(
    image: &dyn BoundedImageReader,
    graph: &ObjectGraph,
    limits: VerificationLimits,
) -> Result<VerificationManifest, VerificationError> {
    validate_limits(limits)?;
    if graph.objects().len() > limits.max_objects {
        return Err(VerificationError::ObjectLimitExceeded {
            actual: graph.objects().len(),
            maximum: limits.max_objects,
        });
    }
    validate_extent_stream_encodings(graph)?;

    let paths = enumerate_paths(graph, limits.max_paths)?;
    let mut extents: BTreeMap<StreamId, Vec<Extent>> = BTreeMap::new();
    for extent in graph.extents().extents() {
        extents.entry(extent.stream).or_default().push(*extent);
    }

    let mut logical_bytes_hashed = 0_u64;
    let mut stream_count = 0_usize;
    let mut objects = Vec::new();
    objects.try_reserve(graph.objects().len()).map_err(|_| {
        VerificationError::ObjectLimitExceeded {
            actual: graph.objects().len(),
            maximum: limits.max_objects,
        }
    })?;

    for object in graph.objects() {
        let mut object_paths = paths
            .get(&object.id)
            .cloned()
            .ok_or(VerificationError::MissingObjectPath(object.id))?;
        object_paths.sort_unstable();
        let mut streams = Vec::new();
        streams.try_reserve(object.streams.len()).map_err(|_| {
            VerificationError::StreamLimitExceeded {
                maximum: limits.max_streams,
            }
        })?;
        for stream in &object.streams {
            stream_count =
                stream_count
                    .checked_add(1)
                    .ok_or(VerificationError::ArithmeticOverflow {
                        calculation: "stream count",
                    })?;
            if stream_count > limits.max_streams {
                return Err(VerificationError::StreamLimitExceeded {
                    maximum: limits.max_streams,
                });
            }
            logical_bytes_hashed = logical_bytes_hashed
                .checked_add(stream.logical_bytes)
                .ok_or(VerificationError::ArithmeticOverflow {
                    calculation: "logical byte total",
                })?;
            if logical_bytes_hashed > limits.max_total_logical_bytes {
                return Err(VerificationError::LogicalByteLimitExceeded {
                    requested: logical_bytes_hashed,
                    maximum: limits.max_total_logical_bytes,
                });
            }
            let digest = match &stream.storage {
                StreamStorage::Resident(bytes) => Sha256::digest(bytes).into(),
                StreamStorage::Extents => hash_extent_stream(
                    image,
                    stream.id,
                    stream.logical_bytes,
                    stream.initialized_bytes,
                    extents
                        .get(&stream.id)
                        .map(Vec::as_slice)
                        .unwrap_or_default(),
                    limits.read_chunk_bytes,
                )?,
            };
            streams.push(StreamManifest {
                name: stream.name.clone(),
                logical_bytes: stream.logical_bytes,
                initialized_bytes: stream.initialized_bytes,
                mapped_bytes: stream.mapped_bytes,
                allocated_bytes: stream.allocated_bytes,
                flags: stream.flags,
                sha256: digest,
            });
        }
        streams.sort_unstable();
        objects.push(ObjectManifest {
            kind: object.kind,
            semantics: object.semantics,
            paths: object_paths,
            streams,
        });
    }
    objects.sort_unstable();
    let metadata_sha256 = hash_metadata(&objects);
    Ok(VerificationManifest {
        objects,
        metadata_sha256,
        logical_bytes_hashed,
    })
}

fn validate_extent_stream_encodings(graph: &ObjectGraph) -> Result<(), VerificationError> {
    for object in graph.objects() {
        for stream in &object.streams {
            if matches!(stream.storage, StreamStorage::Extents)
                && (stream.flags.compressed || stream.flags.encrypted)
            {
                return Err(VerificationError::ExtentStreamRequiresDecoding {
                    stream: stream.id,
                    compressed: stream.flags.compressed,
                    encrypted: stream.flags.encrypted,
                });
            }
        }
    }
    Ok(())
}

fn validate_limits(limits: VerificationLimits) -> Result<(), VerificationError> {
    for (field, value) in [
        ("max_objects", limits.max_objects),
        ("max_paths", limits.max_paths),
        ("max_streams", limits.max_streams),
        ("read_chunk_bytes", limits.read_chunk_bytes),
    ] {
        if value == 0 {
            return Err(VerificationError::InvalidLimit { field });
        }
    }
    if limits.max_total_logical_bytes == 0 {
        return Err(VerificationError::InvalidLimit {
            field: "max_total_logical_bytes",
        });
    }
    Ok(())
}

fn enumerate_paths(
    graph: &ObjectGraph,
    maximum: usize,
) -> Result<BTreeMap<ObjectId, Vec<Utf16Path>>, VerificationError> {
    let mut children: BTreeMap<ObjectId, Vec<(ObjectId, Vec<u16>)>> = BTreeMap::new();
    for entry in graph.entries() {
        children
            .entry(entry.parent)
            .or_default()
            .push((entry.target, entry.name.clone()));
    }
    for values in children.values_mut() {
        values.sort_unstable();
    }

    let mut paths: BTreeMap<ObjectId, Vec<Utf16Path>> = BTreeMap::new();
    let mut seen: BTreeSet<(ObjectId, Utf16Path)> = BTreeSet::new();
    let mut queue = VecDeque::from([(graph.root(), Vec::new())]);
    while let Some((object, path)) = queue.pop_front() {
        if !seen.insert((object, path.clone())) {
            continue;
        }
        if seen.len() > maximum {
            return Err(VerificationError::PathLimitExceeded { maximum });
        }
        paths.entry(object).or_default().push(path.clone());
        if let Some(entries) = children.get(&object) {
            for (target, name) in entries {
                let mut child_path = path.clone();
                child_path.push(name.clone());
                queue.push_back((*target, child_path));
            }
        }
    }
    Ok(paths)
}

fn hash_extent_stream(
    image: &dyn BoundedImageReader,
    stream: StreamId,
    logical_bytes: u64,
    initialized_bytes: u64,
    extents: &[Extent],
    chunk_bytes: usize,
) -> Result<[u8; 32], VerificationError> {
    if logical_bytes != 0 && extents.is_empty() {
        return Err(VerificationError::MissingStreamExtents(stream));
    }
    let mut hasher = Sha256::new();
    let mut position = 0_u64;
    for extent in extents {
        if position >= logical_bytes {
            break;
        }
        if extent.logical_offset != position {
            return Err(VerificationError::ExtentCoverageGap {
                stream,
                expected: position,
                actual: extent.logical_offset,
            });
        }
        let meaningful = extent.length.min(logical_bytes - position);
        let initialized = meaningful.min(initialized_bytes.saturating_sub(position));
        match extent.placement {
            Placement::Physical { byte_offset } => {
                hash_physical(image, &mut hasher, byte_offset, initialized, chunk_bytes)?;
            }
            Placement::Sparse => hash_zeroes(&mut hasher, initialized),
        }
        hash_zeroes(&mut hasher, meaningful - initialized);
        position =
            position
                .checked_add(meaningful)
                .ok_or(VerificationError::ArithmeticOverflow {
                    calculation: "stream hash position",
                })?;
    }
    if position != logical_bytes {
        return Err(VerificationError::ExtentCoverageGap {
            stream,
            expected: logical_bytes,
            actual: position,
        });
    }
    Ok(hasher.finalize().into())
}

fn hash_physical(
    image: &dyn BoundedImageReader,
    hasher: &mut Sha256,
    mut offset: u64,
    mut length: u64,
    chunk_bytes: usize,
) -> Result<(), VerificationError> {
    let reader_max = u64::try_from(image.max_read_bytes()).map_err(|_| {
        VerificationError::ArithmeticOverflow {
            calculation: "reader chunk limit conversion",
        }
    })?;
    if reader_max == 0 {
        return Err(VerificationError::InvalidLimit {
            field: "reader.max_read_bytes",
        });
    }
    while length != 0 {
        let take = length
            .min(
                u64::try_from(chunk_bytes).map_err(|_| VerificationError::ArithmeticOverflow {
                    calculation: "verification chunk conversion",
                })?,
            )
            .min(reader_max);
        let take_usize =
            usize::try_from(take).map_err(|_| VerificationError::ArithmeticOverflow {
                calculation: "verification read length conversion",
            })?;
        hasher.update(image.read_exact_at(offset, take_usize)?);
        offset = offset
            .checked_add(take)
            .ok_or(VerificationError::ArithmeticOverflow {
                calculation: "verification image offset",
            })?;
        length -= take;
    }
    Ok(())
}

fn hash_zeroes(hasher: &mut Sha256, mut length: u64) {
    while length != 0 {
        let take = usize::try_from(length.min(ZEROES.len() as u64))
            .expect("a value capped to the static buffer length fits usize");
        hasher.update(&ZEROES[..take]);
        length -= take as u64;
    }
}

fn hash_metadata(objects: &[ObjectManifest]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    put_u64(&mut hasher, objects.len() as u64);
    for object in objects {
        hasher.update([match object.kind {
            ObjectKind::File => 0,
            ObjectKind::Directory => 1,
        }]);
        hasher.update([
            u8::from(object.semantics.has_security_descriptor),
            u8::from(object.semantics.is_reparse_point),
        ]);
        put_u64(&mut hasher, object.paths.len() as u64);
        for path in &object.paths {
            put_u64(&mut hasher, path.len() as u64);
            for component in path {
                put_u64(&mut hasher, component.len() as u64);
                for unit in component {
                    hasher.update(unit.to_le_bytes());
                }
            }
        }
        put_u64(&mut hasher, object.streams.len() as u64);
        for stream in &object.streams {
            match &stream.name {
                None => hasher.update([0]),
                Some(name) => {
                    hasher.update([1]);
                    put_u64(&mut hasher, name.len() as u64);
                    for unit in name {
                        hasher.update(unit.to_le_bytes());
                    }
                }
            }
            for size in [
                stream.logical_bytes,
                stream.initialized_bytes,
                stream.mapped_bytes,
                stream.allocated_bytes,
            ] {
                put_u64(&mut hasher, size);
            }
            hasher.update([
                u8::from(stream.flags.sparse),
                u8::from(stream.flags.compressed),
                u8::from(stream.flags.encrypted),
            ]);
            hasher.update(stream.sha256);
        }
    }
    hasher.finalize().into()
}

fn put_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::extent::{ExtentGraph, ExtentKind};
    use crate::object::{NamespaceEntry, ObjectGraphLimits, ObjectRecord, ObjectStream};
    use crate::overlay::{OverlayLimits, OverlayPlan, OverlayWrite};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempImage(PathBuf);

    #[derive(Debug)]
    struct PanicOnRead;

    impl BoundedImageReader for PanicOnRead {
        fn len(&self) -> u64 {
            16
        }

        fn max_read_bytes(&self) -> usize {
            16
        }

        fn read_exact_at(&self, _offset: u64, _length: usize) -> Result<Vec<u8>, ImageError> {
            panic!("encoded extent stream reached raw physical image reads")
        }
    }

    impl TempImage {
        fn write(bytes: &[u8]) -> Self {
            let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "starconverter-verify-{}-{id}.img",
                std::process::id()
            ));
            fs::write(&path, bytes).expect("create verification fixture");
            Self(path)
        }
    }

    impl Drop for TempImage {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    fn graph() -> ObjectGraph {
        let extents = ExtentGraph::build(
            vec![
                Extent {
                    stream: StreamId(1),
                    logical_offset: 0,
                    length: 4,
                    placement: Placement::Physical { byte_offset: 4 },
                    kind: ExtentKind::FileData,
                },
                Extent {
                    stream: StreamId(1),
                    logical_offset: 4,
                    length: 4,
                    placement: Placement::Sparse,
                    kind: ExtentKind::FileData,
                },
            ],
            16,
            2,
        )
        .expect("valid extents");
        ObjectGraph::build(
            ObjectId(0),
            vec![
                ObjectRecord {
                    id: ObjectId(0),
                    kind: ObjectKind::Directory,
                    link_count: 0,
                    semantics: ObjectSemantics::default(),
                    streams: Vec::new(),
                },
                ObjectRecord {
                    id: ObjectId(1),
                    kind: ObjectKind::File,
                    link_count: 2,
                    semantics: ObjectSemantics::default(),
                    streams: vec![
                        ObjectStream {
                            id: StreamId(1),
                            name: None,
                            logical_bytes: 7,
                            initialized_bytes: 6,
                            mapped_bytes: 8,
                            allocated_bytes: 4,
                            flags: StreamFlags {
                                sparse: true,
                                ..StreamFlags::default()
                            },
                            storage: StreamStorage::Extents,
                        },
                        ObjectStream {
                            id: StreamId(2),
                            name: Some(vec![u16::from(b'x')]),
                            logical_bytes: 3,
                            initialized_bytes: 3,
                            mapped_bytes: 3,
                            allocated_bytes: 0,
                            flags: StreamFlags::default(),
                            storage: StreamStorage::Resident(b"ads".to_vec()),
                        },
                    ],
                },
            ],
            vec![
                NamespaceEntry {
                    parent: ObjectId(0),
                    target: ObjectId(1),
                    name: vec![u16::from(b'a')],
                },
                NamespaceEntry {
                    parent: ObjectId(0),
                    target: ObjectId(1),
                    name: vec![u16::from(b'b')],
                },
            ],
            extents,
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 2,
                max_streams: 2,
                max_name_code_units: 255,
            },
        )
        .expect("valid object graph")
    }

    fn graph_with_extent_stream_flags(flags: StreamFlags) -> ObjectGraph {
        let base = graph();
        let mut objects = base.objects().to_vec();
        let stream = objects
            .iter_mut()
            .find(|object| object.id == ObjectId(1))
            .and_then(|object| {
                object
                    .streams
                    .iter_mut()
                    .find(|stream| stream.id == StreamId(1))
            })
            .expect("fixture stream");
        stream.flags = flags;
        ObjectGraph::build(
            base.root(),
            objects,
            base.entries().to_vec(),
            base.extents().clone(),
            ObjectGraphLimits {
                max_objects: 2,
                max_entries: 2,
                max_streams: 2,
                max_name_code_units: 255,
            },
        )
        .expect("valid encoded-stream fixture")
    }

    #[test]
    fn hashes_physical_sparse_uninitialized_and_resident_bytes() {
        let temp = TempImage::write(b"xxxxDATAxxxxxxxx");
        let image = ImageFile::open(&temp.0).expect("open fixture");
        let manifest = build_manifest(&image, &graph(), VerificationLimits::default())
            .expect("build manifest");

        assert_eq!(manifest.objects.len(), 2);
        assert_eq!(manifest.logical_bytes_hashed, 10);
        let file = manifest
            .objects
            .iter()
            .find(|object| object.kind == ObjectKind::File)
            .expect("file manifest");
        assert_eq!(file.paths.len(), 2);
        let unnamed = file
            .streams
            .iter()
            .find(|stream| stream.name.is_none())
            .expect("unnamed stream");
        let expected: [u8; 32] = Sha256::digest(b"DATA\0\0\0").into();
        assert_eq!(unnamed.sha256, expected);
        let resident = file
            .streams
            .iter()
            .find(|stream| stream.name.is_some())
            .expect("resident named stream");
        let resident_expected: [u8; 32] = Sha256::digest(b"ads").into();
        assert_eq!(resident.sha256, resident_expected);
    }

    #[test]
    fn refuses_compressed_extent_stream_before_hashing_raw_storage() {
        let encoded = graph_with_extent_stream_flags(StreamFlags {
            sparse: true,
            compressed: true,
            encrypted: false,
        });

        assert!(matches!(
            build_manifest_with_reader(&PanicOnRead, &encoded, VerificationLimits::default()),
            Err(VerificationError::ExtentStreamRequiresDecoding {
                stream: StreamId(1),
                compressed: true,
                encrypted: false,
            })
        ));
    }

    #[test]
    fn refuses_encrypted_extent_stream_before_hashing_raw_storage() {
        let encoded = graph_with_extent_stream_flags(StreamFlags {
            sparse: true,
            compressed: false,
            encrypted: true,
        });

        assert!(matches!(
            build_manifest_with_reader(&PanicOnRead, &encoded, VerificationLimits::default()),
            Err(VerificationError::ExtentStreamRequiresDecoding {
                stream: StreamId(1),
                compressed: false,
                encrypted: true,
            })
        ));
    }

    #[test]
    fn metadata_and_content_are_deterministic_and_detect_changes() {
        let first = TempImage::write(b"xxxxDATAxxxxxxxx");
        let second = TempImage::write(b"xxxxDATExxxxxxxx");
        let first_image = ImageFile::open(&first.0).expect("open first");
        let second_image = ImageFile::open(&second.0).expect("open second");
        let a = build_manifest(&first_image, &graph(), VerificationLimits::default()).unwrap();
        let b = build_manifest(&first_image, &graph(), VerificationLimits::default()).unwrap();
        let changed =
            build_manifest(&second_image, &graph(), VerificationLimits::default()).unwrap();

        assert!(a.equivalent_to(&b));
        assert!(!a.equivalent_to(&changed));
    }

    #[test]
    fn reader_manifest_hashes_overlay_payload_without_changing_base_file() {
        let original = b"xxxxAAAAxxxxxxxx";
        let temp = TempImage::write(original);
        let image = ImageFile::open(&temp.0).expect("open overlay verification fixture");
        let graph = graph();
        let base = build_manifest(&image, &graph, VerificationLimits::default())
            .expect("hash base image through public wrapper");
        let plan = OverlayPlan::build(
            image.len(),
            1,
            vec![OverlayWrite {
                offset: 4,
                bytes: vec![b'B'],
            }],
            OverlayLimits {
                max_writes: 1,
                max_replacement_bytes: 1,
                max_read_bytes: 2,
            },
        )
        .expect("build one-byte overlay");
        let overlaid = {
            let reader = plan.reader(&image).expect("bind overlay reader");
            build_manifest_with_reader(
                &reader,
                &graph,
                VerificationLimits {
                    read_chunk_bytes: 4,
                    ..VerificationLimits::default()
                },
            )
            .expect("hash logical stream through overlay reader")
        };

        let unnamed_digest = |manifest: &VerificationManifest| {
            manifest
                .objects
                .iter()
                .find(|object| object.kind == ObjectKind::File)
                .and_then(|object| object.streams.iter().find(|stream| stream.name.is_none()))
                .map(|stream| stream.sha256)
                .expect("unnamed file stream")
        };
        let base_expected: [u8; 32] = Sha256::digest(b"AAAA\0\0\0").into();
        let overlay_expected: [u8; 32] = Sha256::digest(b"BAAA\0\0\0").into();
        assert_eq!(unnamed_digest(&base), base_expected);
        assert_eq!(unnamed_digest(&overlaid), overlay_expected);
        assert_ne!(unnamed_digest(&base), unnamed_digest(&overlaid));
        drop(image);
        assert_eq!(fs::read(&temp.0).expect("reread base image"), original);
    }

    #[test]
    fn enforces_path_stream_byte_and_read_bounds() {
        let temp = TempImage::write(b"xxxxDATAxxxxxxxx");
        let image = ImageFile::open(&temp.0).unwrap();
        let mut limits = VerificationLimits {
            max_paths: 2,
            ..VerificationLimits::default()
        };
        assert!(matches!(
            build_manifest(&image, &graph(), limits),
            Err(VerificationError::PathLimitExceeded { .. })
        ));

        limits = VerificationLimits {
            max_total_logical_bytes: 9,
            ..VerificationLimits::default()
        };
        assert!(matches!(
            build_manifest(&image, &graph(), limits),
            Err(VerificationError::LogicalByteLimitExceeded { .. })
        ));

        limits = VerificationLimits {
            read_chunk_bytes: 0,
            ..VerificationLimits::default()
        };
        assert!(matches!(
            build_manifest(&image, &graph(), limits),
            Err(VerificationError::InvalidLimit {
                field: "read_chunk_bytes"
            })
        ));
    }
}
