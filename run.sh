if [ "$1" = "sgx-dnet" ]
then
python3 main.py Benchmarks/dnet.wasm sgx_empty_ecall,sgx_ecall_trainer,sgx_ecall_tester,sgx_ecall_classify
fi
if [ "$1" = "sgxwallet" ]
then
python3 main.py Benchmarks/wallet.wasm sgx_ecall_create_wallet,sgx_ecall_show_wallet,sgx_ecall_change_master_password
fi
if [ "$1" = "SGXCryptoFile" ]
then
python3 main.py Benchmarks/sgxcrypto.wasm sgx_sgxDecryptFile,sgx_sgxEncryptFile
fi
if [ "$1" = "verifiable-election" ]
then
python3 main.py Benchmarks/ve.wasm sgx_ecall_gen_credentials,sgx_ecall_unseal_and_export_pub,sgx_ecall_run_election,sgx_ecall_check_voter,sgx_ecall_type_char,sgx_ecall_type_int,sgx_ecall_type_float,sgx_ecall_type_double,sgx_ecall_type_size_t,sgx_ecall_type_wchar_t,sgx_ecall_type_struct,sgx_ecall_type_enum_union,sgx_ecall_pointer_user_check,sgx_ecall_pointer_in,sgx_ecall_pointer_out,sgx_ecall_pointer_in_out,sgx_ecall_pointer_string,sgx_ecall_pointer_string_const,sgx_ecall_pointer_size,sgx_ecall_pointer_count,sgx_ecall_pointer_isptr_readonly,sgx_ocall_pointer_attr,sgx_ecall_array_user_check,sgx_ecall_array_in,sgx_ecall_array_out,sgx_ecall_array_in_out,sgx_ecall_array_isary,sgx_ecall_function_public,sgx_ecall_function_private,sgx_ecall_malloc_free,sgx_ecall_sgx_cpuid,sgx_ecall_exception,sgx_ecall_map,sgx_ecall_increase_counter,sgx_ecall_producer,sgx_ecall_consumer
fi
if [ "$1" = "sgx-log" ]
then
python3 main.py Benchmarks/sl.wasm sgx_process_log,sgx_verify_block_messages,sgx_generate_config,sgx_startup_phase,sgx_reset_block_key,sgx_ecall_type_char,sgx_ecall_type_int,sgx_ecall_type_float,sgx_ecall_type_double,sgx_ecall_type_size_t,sgx_ecall_type_wchar_t,sgx_ecall_type_struct,sgx_ecall_type_enum_union,sgx_ecall_pointer_user_check,sgx_ecall_pointer_in,sgx_ecall_pointer_out,sgx_ecall_pointer_in_out,sgx_ecall_pointer_string,sgx_ecall_pointer_string_const,sgx_ecall_pointer_size,sgx_ecall_pointer_count,sgx_ecall_pointer_isptr_readonly,sgx_ecall_pointer_sizefunc,sgx_ocall_pointer_attr,sgx_ecall_array_user_check,sgx_ecall_array_in,sgx_ecall_array_out,sgx_ecall_array_in_out,sgx_ecall_array_isary,sgx_ecall_function_calling_convs,sgx_ecall_function_public,sgx_ecall_function_private,sgx_ecall_malloc_free,sgx_ecall_sgx_cpuid,sgx_ecall_exception,sgx_ecall_map,sgx_ecall_increase_counter,sgx_ecall_producer,sgx_ecall_consumer,sgx_get_next_block_key,sgx_get_next_message_key,sgx_get_mac,sgx_hash,sgx_compareHashValues,sgx_reverse,sgx_itoa,sgx_myAtoi,sgx_get_hash,sgx_seal_data.126,sgx_seal_and_write
fi
if [ "$1" = "sgx-kmeans" ]
then
python3 main.py Benchmarks/kmeans.wasm sgx_secure_kmeans,sgx_seal,sgx_unseal
fi
if [ "$1" = "sgx-reencrypt" ]
then
python3 main.py Benchmarks/reencrypt.wasm sgx_generate_keypair,sgx_seal_keypair,sgx_unseal_keypair,sgx_reencrypt,sgx_register_key __wasm_call_ctors,sgx_generate_keypair,generate_keypair,sgx_seal_keypair,seal_keypair,sgx_unseal_keypair,unseal_keypair,sgx_reencrypt,reencrypt,sgx_register_key,register_key,untrusted_fs_store,untrusted_fs_load,untrusted_fs_free,time,seal,unseal,fs_store,fs_load,fs_free,unpack_request,key_serialize,key_deserialize,crypto_box_curve25519xsalsa20poly1305_tweet_keypair,set_keypair,unbox,put_key,box,check_policy,.Lunsafe_timestamp_bitcast,decrypt,encrypt,key_free,aes128gcm_plaintext_size,aes128gcm_decrypt,aes128gcm_ciphertext_size,aes128gcm_encrypt,authorized_from,authorized_to,get_key,authorized_clid,unsafe_timestamp,compute_key_id,blake2b_init,blake2b_update,blake2b_final,crypto_box_curve25519xsalsa20poly1305_tweet_open,crypto_box_curve25519xsalsa20poly1305_tweet,randombytes,blake2b_init_param,blake2b_init0,load64,store32,store64,blake2b_init_key,secure_zero_memory,blake2b_increment_counter,blake2b_compress,rotr64,blake2b_set_lastblock,blake2b_set_lastnode,blake2b,crypto_verify_16_tweet,vn,crypto_verify_32_tweet,crypto_core_salsa20_tweet,core,ld32,L32,st32,crypto_core_hsalsa20_tweet,crypto_stream_salsa20_tweet_xor,crypto_stream_salsa20_tweet,crypto_stream_xsalsa20_tweet,crypto_stream_xsalsa20_tweet_xor,crypto_onetimeauth_poly1305_tweet,add1305,crypto_onetimeauth_poly1305_tweet_verify,crypto_secretbox_xsalsa20poly1305_tweet,crypto_secretbox_xsalsa20poly1305_tweet_open,crypto_scalarmult_curve25519_tweet,unpack25519,sel25519,A,Z,S,M,inv25519,pack25519,car25519,crypto_scalarmult_curve25519_tweet_base,crypto_box_curve25519xsalsa20poly1305_tweet_beforenm,crypto_box_curve25519xsalsa20poly1305_tweet_afternm,crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm,crypto_hashblocks_sha512_tweet,dl64,Sigma1,Ch,Sigma0,Maj,sigma0,sigma1,ts64,R,crypto_hash_sha512_tweet,crypto_sign_ed25519_tweet_keypair,scalarbase,pack,set25519,scalarmult,par25519,cswap,add,crypto_sign_ed25519_tweet,reduce,modL,crypto_sign_ed25519_tweet_open,unpackneg,pow2523,neq25519
fi
if [ "$1" = "CryptoEnclave" ]
then
python3 main.py Benchmarks/CE.wasm sgx_dump_key,sgx_gen_key,sgx_gen_sha256,sgx_get_sha256,sgx_gen_hmac_sha256,sgx_get_hmac_sha256,sgx_encrypt_aes_cbc,sgx_decrypt_aes_cbc,sgx_encrypt_aes_ecb,sgx_decrypt_aes_ecb,sgx_oc_cpuidex __wasm_call_ctors,sgx_dump_key,dump_key,sgx_gen_key,gen_key,sgx_gen_sha256,gen_sha256,sgx_get_sha256,get_sha256,sgx_gen_hmac_sha256,gen_hmac_sha256,sgx_get_hmac_sha256,get_hmac_sha256,sgx_encrypt_aes_cbc,encrypt_aes_cbc,sgx_decrypt_aes_cbc,decrypt_aes_cbc,sgx_encrypt_aes_ecb,encrypt_aes_ecb,sgx_decrypt_aes_ecb,decrypt_aes_ecb,print,sgx_oc_cpuidex,sgx_thread_wait_untrusted_event_ocall,sgx_thread_set_untrusted_event_ocall,sgx_thread_setwait_untrusted_events_ocall,sgx_thread_set_multiple_untrusted_events_ocall,printf\(char const*, ...\),zeromem\(void volatile*, unsigned long\),sha256_init\(Hash_state*\),sha256_process\(Hash_state*, unsigned char*, unsigned \),sha256_compress\(Hash_state*, unsigned char*\),sha256_done\(Hash_state*, unsigned char*\),sha256_test\(\),hash_memory\(int, unsigned char*, unsigned long, unsigned char*, unsigned long*\),hmac_init\(Hmac_state*, int, unsigned char*, unsigned long\),hmac_process\(Hmac_state*, unsigned char*, unsigned long\),hmac_done\(Hmac_state*, unsigned char*, unsigned long*\),SETUP\(unsigned char const*, unsigned long, int, Symmetric_key*\),ECB_ENC\(unsigned char const*, unsigned char*, Symmetric_key*\),ECB_DEC\(unsigned char const*, unsigned char*, Symmetric_key*\),cbc_start\(unsigned char*, unsigned char*, unsigned long, int, symmetric_CBC*\),setup_key\(unsigned char*, unsigned char*, unsigned long, int, symmetric_CBC*\),cbc_encrypt\(unsigned char const*, unsigned char*, unsigned long, symmetric_CBC*\),cbc_decrypt\(unsigned char const*, unsigned char*, unsigned long, symmetric_CBC*\)
fi
if [ "$1" = "sgx-pwenclave" ]
then
python3 main.py Benchmarks/pw.wasm sgx_pw_region_enroll,sgx_pw_setup,sgx_pw_check
fi
if [ "$1" = "sgx-deep-learning" ]
then
python3 main.py Benchmarks/isdl.wasm sgx_ecall_train_network,sgx_ecall_test_network,sgx_ecall_thread_enter_enclave_waiting,sgx_ecall_build_network
fi
if [ "$1" = "sgx-biniax2" ]
then
python3 main.py Benchmarks/bi2.wasm sgx_init_store,sgx_free_store,sgx_add_to_store,sgx_get_from_store,sgx_encrypt_store,sgx_decrypt_store,sgx_store_to_bytes
fi
if [ "$1" = "sgx-rsa" ]
then
python3 main.py Benchmarks/rsa.wasm sgx_ecall_get_pubSize,sgx_ecall_gen_pubKey,sgx_ecall_get_prvSize,sgx_ecall_gen_prvKey,sgx_ecall_gen_scratchSize,sgx_ecall_encrypt,sgx_ecall_decryption,sgx_ecall_genKey,sgx_ecall_type_char,sgx_ecall_type_int,sgx_ecall_type_float,sgx_ecall_type_double,sgx_ecall_type_size_t,sgx_ecall_type_wchar_t,sgx_ecall_type_struct,sgx_ecall_type_enum_union,sgx_ecall_pointer_user_check,sgx_ecall_pointer_in,sgx_ecall_pointer_out,sgx_ecall_pointer_in_out,sgx_ecall_pointer_string,sgx_ecall_pointer_string_const,sgx_ecall_pointer_size,sgx_ecall_pointer_count,sgx_ecall_pointer_isptr_readonly,sgx_ocall_pointer_attr,sgx_ecall_array_user_check,sgx_ecall_array_in,sgx_ecall_array_out,sgx_ecall_array_in_out,sgx_ecall_array_isary,sgx_ecall_function_public,sgx_ecall_function_private,sgx_ecall_malloc_free,sgx_ecall_sgx_cpuid,sgx_ecall_exception,sgx_ecall_map,sgx_ecall_increase_counter,sgx_ecall_producer,sgx_ecall_consumer
fi
if [ "$1" = "sgx_protect_file" ]
then
python3 main.py Benchmarks/spf.wasm sgx_ecall_encrypt_file,sgx_ecall_decrypt_file
fi
if [ "$1" = "SGXSSE" ]
then
python3 main.py Benchmarks/sse.wasm sgx_ecall_init,sgx_ecall_query_keyword,sgx_ecall_update_doc
fi