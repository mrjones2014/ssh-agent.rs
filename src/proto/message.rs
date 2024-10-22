use std::{fmt, io::Read};

use serde::{
    de::{self, Visitor},
    Deserialize, Serialize,
};

use super::private_key::PrivateKey;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Identity {
    pub pubkey_blob: Vec<u8>,
    pub comment: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub pubkey_blob: Vec<u8>,
    pub data: Vec<u8>,
    pub flags: u32,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AddIdentity {
    pub privkey: PrivateKey,
    pub comment: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AddIdentityConstrained {
    pub identity: AddIdentity,
    pub constraints: Vec<KeyConstraint>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct RemoveIdentity {
    pub pubkey_blob: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SmartcardKey {
    pub id: String,
    pub pin: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct KeyConstraint {
    pub constraint_type: u8,
    pub constraint_data: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AddSmartcardKeyConstrained {
    pub key: SmartcardKey,
    pub constraints: Vec<KeyConstraint>,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Extension {
    extension_type: String,
    extension_contents: Vec<u8>,
}

// Extension needs special deserialization;
// the derived
// impl<'de> Deserialize<'de> for Extension {
//     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         struct ExtensionVisitor;
//         impl Visitor<'_> for ExtensionVisitor {
//             type Value = Extension;
//
//             fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                 formatter.write_str("a byte array representing Extension")
//             }
//
//             fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
//             where
//                 E: de::Error,
//             {
//                 let mut cursor = std::io::Cursor::new(value);
//
//                 let mut extension_type_length = [0u8; 4];
//                 cursor
//                     .read_exact(&mut extension_type_length)
//                     .map_err(de::Error::custom)?;
//                 let extension_type_length = u32::from_be_bytes(extension_type_length) as usize;
//
//                 let mut extension_type_bytes = vec![0u8; extension_type_length];
//                 cursor
//                     .read_exact(&mut extension_type_bytes)
//                     .map_err(de::Error::custom)?;
//                 let extension_type = String::from_utf8(extension_type_bytes)
//                     .map_err(|_| de::Error::custom("invalid UTF-8 for extension_type"))?;
//
//                 let mut extension_contents = Vec::new();
//                 cursor
//                     .read_to_end(&mut extension_contents)
//                     .map_err(de::Error::custom)?;
//
//                 Ok(Extension {
//                     extension_type,
//                     extension_contents,
//                 })
//             }
//         }
//
//         deserializer.deserialize_bytes(ExtensionVisitor)
//     }
// }

pub type Passphrase = String;
pub type SignatureBlob = Vec<u8>;

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum Message {
    Reserved0,
    Reserved1,
    Reserved2,
    Reserved3,
    Reserved4,
    Failure,
    Success,
    Reserved7,
    Reserved8,
    Reserved9,
    Reserved10,
    RequestIdentities,
    IdentitiesAnswer(Vec<Identity>),
    SignRequest(SignRequest),
    SignResponse(SignatureBlob),
    Reserved15,
    Reserved16,
    AddIdentity(AddIdentity),
    RemoveIdentity(RemoveIdentity),
    RemoveAllIdentities,
    AddSmartcardKey(SmartcardKey),
    RemoveSmartcardKey(SmartcardKey),
    Lock(Passphrase),
    Unlock(Passphrase),
    Reserved24,
    AddIdConstrained(AddIdentityConstrained),
    AddSmartcardKeyConstrained(AddSmartcardKeyConstrained),
    Extension(Extension),
    ExtensionFailure,
}

#[cfg(test)]
mod test {
    use super::{Extension, Message};
    use crate::proto::{from_bytes, to_bytes};
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
    struct AgentForwardingExtension {
        hostkey: String,
        session_identifier: String,
        signature: String,
        is_forwarding: bool,
    }

    // #[test]
    // fn ser_deser_extension() {
    //     let ext_contents = AgentForwardingExtension {
    //         hostkey: "XXXXXXXXXXXXXX".into(),
    //         session_identifier: "XXXXXXXXXXXXXX".into(),
    //         signature: "XXXXXXXXXXXXXX".into(),
    //         is_forwarding: true,
    //     };
    //     let ext_bytes = to_bytes(&ext_contents).unwrap();
    //     let ext = Message::Extension(Extension {
    //         extension_type: "session-bind@openssh.com".into(),
    //         extension_contents: ext_bytes,
    //     });
    //     let ext_bytes = to_bytes(&ext).unwrap();
    //     let message = from_bytes::<Message>(&ext_bytes).unwrap();
    //     let ext_bytes = match message {
    //         Message::Extension(ref ext) => &ext.extension_contents,
    //         _ => panic!("invalid message"),
    //     };
    //     let ext = from_bytes::<AgentForwardingExtension>(&ext_bytes).unwrap();
    //     assert_eq!(ext_contents, ext);
    // }
    #[test]
    fn test() {
        let bytes = vec![
            27, 0, 0, 0, 24, 115, 101, 115, 115, 105, 111, 110, 45, 98, 105, 110, 100, 64, 111,
            112, 101, 110, 115, 115, 104, 46, 99, 111, 109, 0, 0, 0, 51, 0, 0, 0, 11, 115, 115,
            104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 32, 181, 26, 221, 255, 49, 222, 102,
            246, 124, 113, 121, 37, 120, 198, 41, 213, 133, 228, 69, 23, 240, 100, 35, 238, 19, 33,
            17, 73, 251, 45, 247, 200, 0, 0, 0, 64, 241, 83, 5, 1, 81, 99, 244, 121, 16, 203, 177,
            196, 62, 18, 168, 95, 130, 25, 22, 90, 135, 149, 165, 99, 81, 97, 16, 40, 189, 25, 254,
            149, 147, 229, 174, 21, 6, 175, 234, 86, 196, 133, 102, 85, 148, 8, 94, 249, 202, 81,
            250, 72, 213, 0, 211, 0, 34, 7, 101, 58, 36, 161, 41, 166, 0, 0, 0, 83, 0, 0, 0, 11,
            115, 115, 104, 45, 101, 100, 50, 53, 53, 49, 57, 0, 0, 0, 64, 173, 116, 21, 251, 214,
            68, 19, 218, 248, 100, 119, 80, 106, 81, 100, 218, 45, 181, 243, 166, 148, 74, 186,
            178, 250, 80, 222, 227, 24, 57, 160, 36, 253, 36, 79, 40, 141, 53, 94, 47, 225, 82, 42,
            48, 241, 32, 66, 20, 225, 228, 119, 33, 215, 97, 185, 226, 79, 191, 64, 145, 93, 18,
            154, 10, 0,
        ];
        let (bytes_a, bytes_b) = bytes.split_at(84);
        println!("bytes len: {}", bytes_a.len());
        let message = from_bytes::<Message>(&bytes_a).unwrap();
        println!("{message:?}");

        let ext_bytes = match message {
            Message::Extension(ref ext) => &ext.extension_contents,
            _ => panic!("invalid message"),
        };
        println!("bytes len: {}", bytes_b.len());
        // let (bytes_a, bytes_b) = bytes_a.split_at()
        let ext = from_bytes::<Message>(&bytes_b).unwrap();
        println!("{ext:?}");
    }
}
