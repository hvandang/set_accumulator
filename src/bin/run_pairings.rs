extern crate pairing_plus as pairing;
extern crate pointproofs;
extern crate plum;
extern crate itertools;
use pairing::serdes::SerDes;
use pointproofs::pairings::param::paramgen_from_seed;
use pointproofs::pairings::*;
use plum::StandardBloomFilter;
use itertools::Itertools;

fn setcommit(
	prover_params: &ProverParams,
	values: Vec<&str>,
	bloom: &mut plum::StandardBloomFilter<str>
	)-> (Vec<Vec<u8>>,Commitment) {
    for i in 0..values.len() {
    	println!("Item value: {}.", values[i]);
     	bloom.insert(values[i]);
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


fn main() {
    let items_count = 10; //1_000_000;
    let fp_rate = 0.01;
	let vec = vec!["item1", "item2", "item3", "item4"];

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

/*fn main() {
	//setcommit();
    let items_count = 10; //1_000_000;
    let fp_rate = 0.01;
	let vec = vec!["item1", "item2", "item3", "item4"];

    let mut bloom = StandardBloomFilter::<str>::new(items_count, fp_rate);
    
   /* for item in vec {
    	println!("Item value: {}.", item);
    	bloom.insert(item);
	}
    
    let r1=bloom.contains("item1"); /* true */
    println!("{}",r1);
    let r2=bloom.contains("item2"); /* false */
    println!("{}",r2);
    
    println!("Bloom vector size: {}",bloom.optimal_m);
    println!("Bloom vector: {:?}",bloom.bitmap);
    let mut init_values1: Vec<Vec<u8>> = Vec::with_capacity(bloom.optimal_m);
    for i in 0..bloom.optimal_m {
    	let x = bloom.bitmap[i] as i32;
    	let y = format!("{}", x);
    	let v = y.into_bytes();
    	//println!( "{:#?}", v );
        init_values1.push(v);
    }
    println!( "init values 1 {:?}", init_values1 );
    
    let idx = bloom.item_to_indexes("item5");
    println!( "indexes {:?}", idx );
    let n_proof = idx.len();
    println!("number of indexes:{}",n_proof);*/
    
    let n = bloom.optimal_m;//16usize;
    let update_index = n / 2;
    let seed = "This is a very very very very very very long Seed";

    // generate the parameters, and performs pre_computation
    let (mut prover_params, verifier_params) =
        //paramgen_from_seed("This is Leo's Favourite very very long Seed", 0, n).unwrap();
        paramgen_from_seed(seed, 0, n).unwrap();
    prover_params.precomp_256(); // precomp_256, or nothing, as you wish

    // initiate the data to commit
    let mut init_values: Vec<Vec<u8>> = Vec::with_capacity(n);
    println!("Commiting to the following {} strings", n);
    for i in 0..n {
        let s = format!("this is the message number {}", i);
        println!("{}", s);
        init_values.push(s.into_bytes());
    }
   	println!( "init values {:#?}", init_values );

    // generate the commitment, and (de)serialize it
   // let old_com = Commitment::new(&prover_params, &init_values).unwrap();
    
    //let old_com = Commitment::new(&prover_params, &init_values1).unwrap();
    let (init_values2,old_com) = setcommit(&prover_params,vec,items_count,fp_rate);
    
    let mut old_commitment_bytes: Vec<u8> = vec![];
    assert!(old_com.serialize(&mut old_commitment_bytes, true).is_ok());
    assert_eq!(
        old_com,
        Commitment::deserialize(&mut old_commitment_bytes[..].as_ref(), true).unwrap()
    );

    println!("\nCommitment:  {:02x?}\n", old_commitment_bytes);
    println!("Bloom filter array: {:?}", init_values2);

	let check_item="item1";
	let proofs: Vec<Proof> =setprove(&prover_params, &init_values2, check_item, items_count, fp_rate);
	println!("Proofs: {:?}", proofs);
    
	/*let mut proofs: Vec<Proof> = Vec::with_capacity(n_proof);
    for i in 0..n_proof {
        proofs.push(Proof::new(&prover_params, &init_values1, idx[i]).unwrap());
        let mut proof_bytes: Vec<u8> = vec![];
        assert!(proofs[i].serialize(&mut proof_bytes, true).is_ok());
        println!("Old Proof {}: {:02x?}", i, proof_bytes);
        assert_eq!(
            proofs[i],
            Proof::deserialize(&mut proof_bytes[..].as_ref(), true).unwrap()
        );
        assert!(proofs[i].verify(&verifier_params, &old_com, [49], idx[i]));
    }*/
    
/*    // generate the proof, (de)serialize it, and verify it
    let mut proofs: Vec<Proof> = Vec::with_capacity(n);
    for i in 0..n {
        proofs.push(Proof::new(&prover_params, &init_values, i).unwrap());
        let mut proof_bytes: Vec<u8> = vec![];
        assert!(proofs[i].serialize(&mut proof_bytes, true).is_ok());
        println!("Old Proof {}: {:02x?}", i, proof_bytes);
        assert_eq!(
            proofs[i],
            Proof::deserialize(&mut proof_bytes[..].as_ref(), true).unwrap()
        );
        assert!(proofs[i].verify(&verifier_params, &old_com, &init_values[i], i));
    }

    let new_value = format!("\"this is new message number {}\"", update_index);
    println!("\nUpdating string {} to {}\n", update_index, new_value);

    // update the commitment to the new value, and (de)serialize it
    let mut new_com = old_com;
    new_com
        .update(
            &prover_params,
            update_index,
            &init_values[update_index][..].as_ref(),
            &new_value.as_ref(),
        )
        .unwrap();
    let mut new_commitment_bytes: Vec<u8> = vec![];
    assert!(new_com.serialize(&mut new_commitment_bytes, true).is_ok());
    assert_eq!(
        new_com,
        Commitment::deserialize(&mut new_commitment_bytes[..].as_ref(), true).unwrap()
    );

    // verifies new proof against new commitment and new value
    assert!(proofs[update_index].verify(&verifier_params, &new_com, &new_value, update_index));

    // verifies new proof against new commitment and old value -- must fail
    assert!(!proofs[update_index].verify(
        &verifier_params,
        &new_com,
        &init_values[update_index],
        update_index
    ));

    for i in 0..n {
        // verifies the old proofs against new commitment -- must fail
        if i != update_index {
            assert!(!proofs[i].verify(&verifier_params, &new_com, &init_values[i], i));
        }

        // update the proofs to the new value
        assert!(proofs[i]
            .update(
                &prover_params,
                i,
                update_index,
                &init_values[update_index][..].as_ref(),
                &new_value.as_ref(),
            )
            .is_ok());
        // the updated proof should pass verification against the new commitment
        if i != update_index {
            assert!(proofs[i].verify(&verifier_params, &new_com, &init_values[i], i));
        }

        // (de)serialization
        let mut proof_bytes: Vec<u8> = vec![];
        assert!(proofs[i].serialize(&mut proof_bytes, true).is_ok());
        println!("New Proof {}: {:02x?}", i, proof_bytes);
        assert_eq!(
            proofs[i],
            Proof::deserialize(&mut proof_bytes[..].as_ref(), true).unwrap()
        );
    }

    // finished
    println!("\nNi hao, Algorand");*/
}*/
