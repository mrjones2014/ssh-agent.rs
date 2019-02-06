pub mod ser;
pub mod de;
pub mod message;
pub mod error;
pub mod private_key;
pub mod public_key;

pub use self::ser::to_bytes;
pub use self::de::from_bytes;

use serde::{Serialize, Deserialize};
use self::error::ProtoResult;

pub trait Blob: Sized {
    fn to_blob(&self) -> ProtoResult<Vec<u8>>;
    fn from_blob(blob: &[u8]) -> ProtoResult<Self>;
}

impl<'a, T: Serialize + Deserialize<'a>> Blob for T {
    fn to_blob(&self) -> ProtoResult<Vec<u8>> {
        to_bytes(self)
    }
    
    fn from_blob(blob: &[u8]) -> ProtoResult<T> {
        from_bytes(blob)
    }
}

#[cfg(test)]
mod tests {
    use super::{to_bytes, from_bytes, Blob};
    use super::public_key::{PublicKey, RsaKey};
    use super::message::{Message, SignRequest, SignResponse, Identity};

    #[test]
    fn blob_serialization() {
        let key = PublicKey::Rsa(RsaKey {
            e: vec![1, 0, 1],
            n: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        });
        let serde_key = PublicKey::from_blob(&key.to_blob().unwrap()).unwrap();
        assert_eq!(key, serde_key);
    }
    
    #[test]
    fn message_serialization() {
        let key = PublicKey::Rsa(RsaKey {
            e: vec![1, 0, 1],
            n: vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        });
        
        let sign_req = Message::SignRequest(
            SignRequest {
                key_blob: key.to_blob().unwrap(),
                data: b"data".to_vec(),
                flags: 24
            }
        );
        let serde_sign_req: Message = from_bytes(&to_bytes(&sign_req).unwrap()).unwrap();
        assert_eq!(sign_req, serde_sign_req);
        
        let sign_resp = Message::SignResponse(
            SignResponse {
                signature: b"signature".to_vec()
            }
        );
        let serde_sign_resp: Message = from_bytes(&to_bytes(&sign_resp).unwrap()).unwrap();
        assert_eq!(sign_resp, serde_sign_resp);
        
        let success = Message::Success;
        let serde_success: Message = from_bytes(&to_bytes(&success).unwrap()).unwrap();
        assert_eq!(success, serde_success);
        
        let ident_ans = Message::IdentitiesAnswer(
            vec![
                Identity {
                    key_blob: b"key_blob_1".to_vec(),
                    comment: "comment_1".to_string()
                },
                Identity {
                    key_blob: b"key_blob_2".to_vec(),
                    comment: "".to_string()
                }
            ]
        );
        let serde_ident_ans: Message = from_bytes(&to_bytes(&ident_ans).unwrap()).unwrap();
        assert_eq!(ident_ans, serde_ident_ans);
    }
}