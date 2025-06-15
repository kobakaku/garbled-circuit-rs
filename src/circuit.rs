use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Gate {
    pub id: u32,
    #[serde(rename = "type")]
    pub gate_type: String,
    #[serde(rename = "in")]
    pub inputs: Vec<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Circuit {
    pub id: String,
    pub gates: Vec<Gate>,
    pub alice: Option<Vec<u32>>,
    pub bob: Option<Vec<u32>>,
    pub out: Vec<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CircuitCollection {
    pub name: String,
    pub circuits: Vec<Circuit>,
}

impl Circuit {
    pub fn from_json_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Vec<Circuit>, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let collection: CircuitCollection = serde_json::from_str(&contents)?;
        Ok(collection.circuits)
    }

    pub fn load_single<P: AsRef<Path>>(path: P) -> Result<Circuit, Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(path)?;
        let circuit: Circuit = serde_json::from_str(&contents)?;
        Ok(circuit)
    }
}
