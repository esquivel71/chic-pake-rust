#[derive(Debug, PartialEq)]
/// Error types for the failure modes
pub enum KyberError {
    /// One or more inputs to a function are incorrectly sized. A likely cause of this is two parties using different security
    /// levels while trying to negotiate a key exchange.
    InvalidInput,
    /// The ciphertext was unable to be authenticated.
    /// The shared secret was not decapsulated.
    Decapsulation,
    /// Error trying to fill random bytes (i.e external (hardware) RNG modules can fail).
    RandomBytesGeneration,
}

impl core::fmt::Display for KyberError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            KyberError::InvalidInput => write!(f, "Function input is of incorrect length"),
            KyberError::Decapsulation => write!(
                f,
                "Decapsulation Failure, unable to obtain shared secret from ciphertext"
            ),
            KyberError::RandomBytesGeneration => {
                write!(f, "Random bytes generation function failed")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum PakeError {
    InvalidInput,
    KemError,
    HicError(HicError),
    Other
}

impl core::fmt::Display for PakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            PakeError::InvalidInput => write!(f, "Function input is of incorrect length"),
            PakeError::KemError => {
                write!(f, "An error ocurred in a KEM function!")
            }
            PakeError::HicError(e) => {
                write!(f, "An error ocurred in a HIC function! Error: {:?}", e)
            }
            PakeError::Other => {
                write!(f, "An error occurred in a PAKE function")
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum HicError {
    InvalidInput,
    Other
}

impl core::fmt::Display for HicError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            HicError::InvalidInput => write!(f, "Function input is of incorrect length"),
            HicError::Other => {
                write!(f, "An error occurred in a HIC function")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KyberError {}
