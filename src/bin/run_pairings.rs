extern crate pairing_plus as pairing;
extern crate pointproofs;
extern crate plum;
extern crate itertools;
use pairing::serdes::SerDes;
use pointproofs::pairings::param::paramgen_from_seed;
use pointproofs::pairings::*;
use plum::StandardBloomFilter;
use itertools::Itertools;

//read file line by line
//use std::fs::File;
//use std::io::{self, BufRead};
//use std::path::Path;

//read csv
//extern crate csv;
//use csv::Error;

//use std::env;
//use std::error::Error;
//use std::ffi::OsString;
//use std::fs::File;
//use std::process;

fn setcommit(
	prover_params: &ProverParams,
	values: Vec<String>,
	bloom: &mut plum::StandardBloomFilter<str>
	)-> (Vec<Vec<u8>>,Commitment) {
    for i in 0..values.len() {
    	println!("Item value: {}.", values[i]);
     	bloom.insert(&values[i]);
    }
		
	println!("Bloom vector size: {}",bloom.optimal_m);	    
	println!("Bloom vector: {:?}",bloom.bitmap);
	let mut init_values: Vec<Vec<u8>> = Vec::with_capacity(bloom.optimal_m);
	for i in 0..bloom.optimal_m {
    	let x = bloom.bitmap[i] as i32;
    	let y = format!("{}", x);
	    let v = y.into_bytes();
	    //println!( "{:#?}", v );
	    init_values.push(v);
	 }
     println!( "init values  {:?}", init_values );
     // generate the commitment, and (de)serialize it
     let com = Commitment::new(&prover_params, &init_values).unwrap();
   	
   	 return (init_values,com);
}

fn settobloom(
        items: &Vec<&str>,
        bloom: &mut plum::StandardBloomFilter<str>
    )-> Vec<usize> {
    let mut res: Vec<usize>=vec![];
    for i in items {
	    let mut idx = bloom.item_to_indexes(i);
	    println!( "indexes {:?}", idx );
	    res.append(&mut idx);
    }
    let res: Vec<_> = res.into_iter().unique().collect();
    println!( "combined indexes {:?}", res );
    return res;
}

fn setprove(
        prover_params: &ProverParams,
        init_values: &Vec<Vec<u8>>,
        //item: &str,
        items: &Vec<&str>,
        bloom: &mut plum::StandardBloomFilter<str>,
        com: &Commitment
    )-> Proof {
    //let idx = bloom.item_to_indexes(item);
    let idx = settobloom(items,bloom);
    println!( "indexes {:?}", idx );
    
    let n_proof = idx.len();
    println!("number of indexes:{}",n_proof);
    
    let mut proofs: Vec<Proof> = Vec::with_capacity(n_proof);

    let mut value_sub_vector: Vec<&[u8]> = vec![];
    for index in &idx {
        let proof = Proof::new(&prover_params, &init_values, *index).unwrap();
        proofs.push(proof);
        value_sub_vector.push(&[49]);
    }
            
    //println!("value sub vector:{:?}",value_sub_vector);
	let agg_proof=Proof::same_commit_aggregate(&com,
		&proofs,
		&idx,
    	&value_sub_vector,
    	bloom.optimal_m).unwrap();
    	
   	let mut proof_bytes: Vec<u8> = vec![];
    assert!(agg_proof.serialize(&mut proof_bytes, true).is_ok());
    println!("Aggregated Proof: {:02x?}", proof_bytes);
    
   	return agg_proof;
}

fn setverify(
        verifier_params: &VerifierParams,
        com: &Commitment,
        //item: &str,
        items: &Vec<&str>,
        bloom: &mut plum::StandardBloomFilter<str>,
        agg_proof: Proof
    )-> bool {

   // let idx = bloom.item_to_indexes(item);
    let idx = settobloom(items,bloom);
    println!("Indexes of item: {:?}",idx);
    let n_proof = idx.len();
    	
    let value_sub_vector = vec![&[49]; n_proof];
    let res=agg_proof.same_commit_batch_verify(&verifier_params, 
    	&com, 
    	&idx, 
    	&value_sub_vector);
  	
  	/* //Verify each proof
	let mut res;
 	for i in 0..n_proof {
        res = proofs[i].verify(&verifier_params, &com, [49], idx[i]);
        println!("Proof at index {}:{}",idx[i],res);
        if res==false{
        	return false;
		}
    }*/
    return res;
}

/*
fn testcommit(n: u8, S: &mut [String]) {
    let items_count = 10; //1_000_000;
    let fp_rate = 0.01;
    let mut bloom = StandardBloomFilter::<str>::new(items_count, fp_rate);

    let n = bloom.optimal_m;//16usize;
    let seed = "This is a very very very very very very long Seed";
    // generate the parameters, and performs pre_computation
    let (mut prover_params, verifier_params) =
        //paramgen_from_seed("This is Leo's Favourite very very long Seed", 0, n).unwrap();
        paramgen_from_seed(seed, 0, n).unwrap();
    prover_params.precomp_256(); // precomp_256, or nothing, as you wish

    let (init_values,old_com) = setcommit(&prover_params,vec,&mut bloom);

    let mut old_commitment_bytes: Vec<u8> = vec![];
    assert!(old_com.serialize(&mut old_commitment_bytes, true).is_ok());
    assert_eq!(
        old_com,
        Commitment::deserialize(&mut old_commitment_bytes[..].as_ref(), true).unwrap()
    );

    println!("\nCommitment:  {:02x?}\n", old_commitment_bytes);
    println!("Bloom filter array: {:?}", init_values);

    return old_commitment_bytes;
}
*/

/*
//https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html
// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

//https://doc.rust-lang.org/rust-by-example/std_misc/file/read_lines.html
fn read_file(filename: &str){
    // File hosts must exist in current path before this produces output
    if let Ok(lines) = read_lines(filename) {
        // Consumes the iterator, returns an (Optional) String
        for line in lines {
            if let Ok(ip) = line {
                println!("{}", ip);
            }
        }
    }
}*/

//https://docs.rs/csv/1.0.0/csv/tutorial/index.html#reading-csv
/*fn read_csv(file_path: &str){
    //let file = File::open(file_path);
    let csv = "year,make,model,description
        1948,Porsche,356,Luxury sports car
        1967,Ford,Mustang fastback 1967,American car";

    //let mut rdr = csv::Reader::from_reader(csv.as_bytes());
    let rdr = [1,2];
    for result in rdr.records() {
        let record = result;
        println!("{:?}", record);
    }
}*/

//https://dev.to/0xbf/day10-read-csv-with-csv-crate-100dayofrust-158f
fn read_csv(filepath:&str)-> Vec<String> {
    let mut reader = csv::ReaderBuilder::new()
                        .has_headers(false)
                        .from_path(filepath)
                        .expect("Cannot read file");
    let mut vec = Vec::new();
    //let mut total_score = 0;
    //let mut total_count = 0;
    for record in reader.records() {
        //total_score += record.unwrap()[0].trim().parse::<i32>().unwrap();
        //total_count += 1;
        let x: String=record.unwrap()[0].to_owned();
        vec.push(x);
    }
    //println!("Total score: {} Avg score: {}",
    //         total_score,
    //         (total_score as f32) / (total_count as f32));
    return vec;
}

fn main() {
    // let vec=read_csv("../../data/input.csv");
    
    let items_count = 10; //1_000_000;
    let fp_rate = 0.01;
	let mut vec: Vec<String> = Vec::new();
    for i in 0..10 {
        vec.push(String::from("item"));
        vec[i].push_str(&i.to_string());
    }

    let mut bloom = StandardBloomFilter::<str>::new(items_count, fp_rate);
    
    let n = bloom.optimal_m;//16usize;
    let seed = "This is a very very very very very very long Seed";
    // generate the parameters, and performs pre_computation
    let (mut prover_params, verifier_params) =
        //paramgen_from_seed("This is Leo's Favourite very very long Seed", 0, n).unwrap();
        paramgen_from_seed(seed, 0, n).unwrap();
    prover_params.precomp_256(); // precomp_256, or nothing, as you wish

    let (init_values,old_com) = setcommit(&prover_params,vec,&mut bloom);
    
    let mut old_commitment_bytes: Vec<u8> = vec![];
    assert!(old_com.serialize(&mut old_commitment_bytes, true).is_ok());
    /*
    assert_eq!(
        old_com,
        Commitment::deserialize(&mut old_commitment_bytes[..].as_ref(), true).unwrap()
    );*/

    println!("\nCommitment:  {:02x?}\n", old_commitment_bytes);
    println!("Bloom filter array: {:?}", init_values);
    
    let check_items = vec!["item1","item5"];
    let agg_proof=setprove(&prover_params, 
    	&init_values, 
		&check_items,
		&mut bloom,
		&old_com);
		
	let res = setverify(&verifier_params,
        &old_com,
        &check_items,
        &mut bloom,
        agg_proof);
	println!("result of verification:{}",res);

    /*let check_item="item1";
	let agg_proof=setprove(&prover_params, 
		&init_values, 
		check_item,
		&mut bloom,
		&old_com);
	
	let res = setverify(&verifier_params,
        &old_com,
        check_item,
        &mut bloom,
        agg_proof);
	println!("result of verification:{}",res);
	
	let set1=vec!["item1","item5"];
	settobloom(set1,&mut bloom);*/

}

