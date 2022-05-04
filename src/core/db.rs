use std::process::exit;
use serde::{Serialize, Deserialize};

pub struct Db {
    pub db: sled::Db,
}

impl Db {
    pub fn new(db_path: &str) -> Self {
        log::info!("create seld db");
        let db = match sled::open(db_path) {
            Ok(db) => {
                db
            }
            Err(errors) => {
                log::error!("open data file error, {}", errors);
                exit(1)
            }
        };
        Self {
            db
        }
    }

    pub fn get_vec(&self, key: &str) -> Option<Vec<u8>> {
        return match self.db.get(key) {
            Ok(result) => {
                if let Some(vec) = result {
                    Some(vec.to_vec())
                } else {
                    None
                }
            }
            Err(error) => {
                log::info!("get key error, {}", error);
                None
            }
        };
    }

    // TODO: as a common func
    pub fn parse_value<'a, T>(&self, vec: &'a Option<Vec<u8>>) -> Option<T> where T: Deserialize<'a> {
        return match vec {
            Some(vec_u8) => {
                match serde_json::from_slice::<T>(vec_u8.as_slice()) {
                    Ok(result) => Some(result),
                    Err(error) => {
                        log::info!("deserialize from slice error, {}", error);
                        None
                    }
                }
            }
            None => {
                None
            }
        };
    }

    pub fn set<T>(&self, key: &str, val: T) -> anyhow::Result<()> where T: Serialize {
        self.set_with_ref(key, &val)
    }

    pub fn set_with_ref<T>(&self, key: &str, val: &T) -> anyhow::Result<()> where T: Serialize {
        let vec = match serde_json::to_vec(val) {
            Ok(vec) => {
                vec
            }
            Err(error) => {
                return Err(anyhow::anyhow!(error));
            }
        };

        return match self.db.insert(key, vec) {
            Ok(_) => {
                Ok(())
            }
            Err(error) => Err(anyhow::anyhow!(error))
        };
    }
}

#[cfg(test)]
mod tests{
    use crate::core::db::Db;
    use crate::setup_log;

    #[test]
    pub fn test_db() {
        setup_log();
        let db = Db::new("tmp/db");
        db.set("host", "www.baidu.com");
        let vec_opt = db.get_vec("host");
        let value = db.parse_value::<String>(&vec_opt);
        println!("get host value = {:?}", value.unwrap());
    }
}