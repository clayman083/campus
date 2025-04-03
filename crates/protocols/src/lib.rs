pub use self::protos::*;

mod protos {
    pub mod passport_proto {
        pub const FILE_DESCRIPTOR_SET: &[u8] =
            tonic::include_file_descriptor_set!("passport_descriptor");
    }

    pub mod passport {
        tonic::include_proto!("passport");
    }
}
