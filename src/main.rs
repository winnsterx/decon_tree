use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

// DeconTree struct that contains hashed leafs and root

// Deterministic. Using the order-agnostic property of XOR operations,
// we can derive the same Merkle root for the same, but unordered elements. 
// We XOR pairs of left and right hashed leaf nodes at each level until we reach the 
// topmost level. See the tests for examples of deterministic property.

// Confidentiality is implemented using a secret pseudorandom salt generated from 
// the timestamp. The salt isnt stored or acccessible within any DeconTree instance.
// In practice, the salt is generated one-time and stored in a centralised, secure database.
// If compromised, confidenlity for all DeconTree instances will be lost. 

// To handle odd number of leaves, I pad the nodes with a leaf with value of hash(0||salt).
// At every level, such padding is applied to ensure that the correct XOR can be calculated. 

#[derive(Debug)]
struct DeconTree {
    leafs: VecDeque<String>,
    root: String,
}

impl DeconTree {
    // Instantiates a new instance of DeconTree Object with leafs
    // leafs: hashes of (data || secret_salt)
    // root: root of the hashed data, generated w XOR to get order-agnosticity
    pub fn new(data: Vec<&str>, salt: &str) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let mut hashes: VecDeque<String> = data.iter().map(|&s| Self::hash(s, salt)).collect();
        let leafs = hashes.clone();
        let mut root = Self::generate_next_roots(&mut hashes, &salt);
        
        Some(DeconTree {
            leafs,
            root: root.pop_front().expect("Get root."),
        })
    }

    // Returns a sha256 hash of value
    fn hash(value: &str, salt: &str) -> String {
        let mut sha256 = Sha256::new();
        let salted_value = format!("{}{}", value, salt);
        sha256.update(salted_value);
        let hash_val: String = format!("{:X}", sha256.finalize());
        hash_val
    }

    // Returns a pseudorandom salt using the current time 
    fn generate_salt() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Get time for randomness.")
            .subsec_nanos();    
        let time = format!("{}", nanos);
        Self::hash(&time, &time)
    }

    // Pads uneven number of nodes with a node of empty data
    fn ensure_even_nodes(nodes: &mut VecDeque<String>, salt: &str) {
        if nodes.len() % 2 != 0 {
            nodes.push_back(Self::hash("0", &salt));
        }
    }

    // XORs two strings by first converting them into bytes
    fn xor_strings(a: String, b: String) -> String {
        a.bytes()
            .zip(b.bytes())
            .map(|(byte_a, byte_b)| byte_a ^ byte_b)
            .map(char::from)
            .collect()
    }

    // Returns the final root by deriving XORs of every two leaves
    // (left & right) recursively
    fn generate_next_roots(nodes: &mut VecDeque<String>, salt: &str) -> VecDeque<String> {
        // if there is 0 or 1 node, we reached the top-most root so we return.
        if nodes.len() < 2 {
            return nodes.clone();
        }

        Self::ensure_even_nodes(nodes, &salt);
        let mut next_roots = VecDeque::new();

        // while there is 2+ nodes, we XOR to get their parent and use it for the next recursion
        while nodes.len() > 1 {
            let left = nodes.pop_front().expect("Get left node.");
            let right = nodes.pop_front().expect("Get right node.");
            let combined = Self::xor_strings(left, right); //XOR
            next_roots.push_back(combined);
        }

        // recurse on the next level of roots (XOR of this level's pairs of leafs)
        Self::generate_next_roots(&mut next_roots, &salt)
    }
}

fn main() {
    // Example use case 
    let leaves_a = vec!["apple", "banana", "cherry", "date", "mango"];
    let leaves_b = vec!["banana", "cherry", "apple", "date", "mango"];

    // Salt would come from a centralised server and used in a secret & secure way. 
    // We are generating it here for ease. 
    let salt = DeconTree::generate_salt();

    let tree_a = DeconTree::new(leaves_a, &salt).expect("DeconTree unwrapped.");
    let tree_b = DeconTree::new(leaves_b, &salt).expect("DeconTree unwrapped.");

    if tree_a.root == tree_b.root {
        println!("Tree A = Tree B");
    }
}

#[cfg(test)]
mod tests {
    use crate::DeconTree;
    #[test]
    fn test_same_elem_diff_order() {
        let leaves_a = vec!["apple", "banana", "cherry", "date", "mango"];
        let leaves_b = vec!["banana", "cherry", "apple", "date", "mango"];
        let salt: String = DeconTree::generate_salt();
        let tree_a = DeconTree::new(leaves_a, &salt).expect("DeconTree unwrapped.");
        let tree_b = DeconTree::new(leaves_b, &salt).expect("DeconTree unwrapped.");
        assert_eq!(tree_a.root, tree_b.root);
    }

    #[test]
    fn test_empty_strings_diff_order() {
        let leaves_a = vec!["", "a"];
        let leaves_b = vec!["a", ""];
        let salt: String = DeconTree::generate_salt();
        let tree_a = DeconTree::new(leaves_a, &salt).expect("DeconTree unwrapped.");
        let tree_b = DeconTree::new(leaves_b, &salt).expect("DeconTree unwrapped.");
        assert_eq!(tree_a.root, tree_b.root);
    }


    #[test]
    fn test_zero_string_diff_order() {
        let leaves_a = vec!["hello world"];
        let leaves_b = vec!["0", "hello world"];
        let salt: String = DeconTree::generate_salt();
        let tree_a = DeconTree::new(leaves_a, &salt).expect("DeconTree unwrapped.");
        let tree_b = DeconTree::new(leaves_b, &salt).expect("DeconTree unwrapped.");
        assert_ne!(tree_a.root, tree_b.root);
    }

    #[test]
    fn test_same_elem_same_order_number() {
        let leaves_a = vec!["123", "456"];
        let leaves_b = vec!["123", "456"];
        let salt: String = DeconTree::generate_salt();
        let tree_a = DeconTree::new(leaves_a, &salt).expect("DeconTree unwrapped.");
        let tree_b = DeconTree::new(leaves_b, &salt).expect("DeconTree unwrapped.");
        assert_eq!(tree_a.root, tree_b.root);
    }

    #[test]
    fn test_diff_elem_diff_order() {
        let leaves_a = vec!["apple", "cherry", "date", "mango"];
        let leaves_b = vec!["banana", "cherry", "apple", "date", "mango"];
        let salt: String = DeconTree::generate_salt();
        let tree_a = DeconTree::new(leaves_a, &salt).expect("DeconTree unwrapped.");
        let tree_b = DeconTree::new(leaves_b, &salt).expect("DeconTree unwrapped.");
        assert_ne!(tree_a.root, tree_b.root);
    }

    #[test]
    fn test_empty_data() {
        let leaves_a = vec![];
        let salt: String = DeconTree::generate_salt();
        let tree_a = DeconTree::new(leaves_a, &salt);
        assert!(tree_a.is_none(), "Empty data returns None.");
    }

    // flaw of this system, cannot distinugish between the difference below
    #[test]
    fn test_flaw_odd_zeros() {
        let leaves_a = vec!["0", "0", "0"];
        let leaves_b = vec!["0", "0", "0", "0"];
        let salt: String = DeconTree::generate_salt();
        let tree_a = DeconTree::new(leaves_a, &salt).expect("DeconTree unwrapped.");
        let tree_b = DeconTree::new(leaves_b, &salt).expect("DeconTree unwrapped.");
        assert_eq!(tree_a.root, tree_b.root);
    }
}
