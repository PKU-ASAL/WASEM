(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32) (result i64)))
  (type (;6;) (func))
  (type (;7;) (func (param i32 i32) (result i32)))
  (type (;8;) (func (param i32 i32 i32 i32)))
  (type (;9;) (func (param i32 i32 i64) (result i32)))
  (type (;10;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;11;) (func (param i32 i64) (result i64)))
  (type (;12;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;13;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;14;) (func (param i32) (result i32)))
  (type (;15;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;16;) (func (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;17;) (func (param i32 i32 i32 i32 i64) (result i32)))
  (type (;18;) (func (param i32 i32 i64)))
  (type (;19;) (func (param i32 i32)))
  (type (;20;) (func (param i32 i32 i32)))
  (type (;21;) (func (param i32 i64)))
  (type (;22;) (func (param i32 i64 i32 i64 i32 i64)))
  (type (;23;) (func (param i32 i64 i32 i64 i32 i64 i32 i64)))
  (type (;24;) (func (param f32)))
  (type (;25;) (func (param f64)))
  (type (;26;) (func (param i64)))
  (type (;27;) (func (result i32)))
  (type (;28;) (func (result i64)))
  (type (;29;) (func (param i32 i64 i32) (result i32)))
  (type (;30;) (func (param f64 f64) (result i32)))
  (type (;31;) (func (param f32 f32) (result i32)))
  (type (;32;) (func (param i32 i32 i32 i32 i32 i32)))
  (type (;33;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;34;) (func (param i32 i32 i32 i32 i32)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "malloc" (func $malloc (type 1)))
  (import "env" "memcpy_s" (func $memcpy_s (type 2)))
  (import "env" "free" (func $free (type 3)))
  (import "env" "memset" (func $memset (type 4)))
  (import "env" "strlen" (func $strlen (type 5)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 1)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 6)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 7)))
  (import "env" "abort" (func $abort (type 6)))
  (import "env" "__assert" (func $__assert (type 8)))
  (import "env" "memcpy" (func $memcpy (type 4)))
  (import "env" "__stack_chk_fail" (func $__stack_chk_fail (type 6)))
  (import "env" "strncpy" (func $strncpy (type 9)))
  (import "env" "_Znam" (func $operator_new___unsigned_long_ (type 1)))
  (import "env" "_ZdaPv" (func $operator_delete___void*_ (type 3)))
  (import "env" "vsnprintf" (func $vsnprintf (type 10)))
  (import "env" "strnlen" (func $strnlen (type 11)))
  (import "env" "sgx_create_rsa_key_pair" (func $sgx_create_rsa_key_pair (type 12)))
  (import "env" "sgx_calc_sealed_data_size" (func $sgx_calc_sealed_data_size (type 7)))
  (import "env" "sgx_seal_data" (func $sgx_seal_data (type 13)))
  (import "env" "sgx_get_add_mac_txt_len" (func $sgx_get_add_mac_txt_len (type 14)))
  (import "env" "sgx_get_encrypt_txt_len" (func $sgx_get_encrypt_txt_len (type 14)))
  (import "env" "sgx_unseal_data" (func $sgx_unseal_data (type 15)))
  (import "env" "sgx_create_rsa_priv1_key" (func $sgx_create_rsa_priv1_key (type 16)))
  (import "env" "sgx_rsa_priv_decrypt_sha256" (func $sgx_rsa_priv_decrypt_sha256 (type 17)))
  (import "env" "sgx_read_rand" (func $sgx_read_rand (type 0)))
  (import "env" "sgx_cpuid" (func $sgx_cpuid (type 7)))
  (import "env" "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6__initEPKcm" (func $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_ (type 18)))
  (import "env" "__cxa_allocate_exception" (func $__cxa_allocate_exception (type 1)))
  (import "env" "_ZNSt13runtime_errorC1ERKNSt3__112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEE" (func $std::runtime_error::runtime_error_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_ (type 19)))
  (import "env" "_ZNSt13runtime_errorD1Ev" (func $std::runtime_error::~runtime_error__ (type 3)))
  (import "env" "__cxa_throw" (func $__cxa_throw (type 20)))
  (import "env" "__cxa_begin_catch" (func $__cxa_begin_catch (type 14)))
  (import "env" "_ZSt9terminatev" (func $std::terminate__ (type 6)))
  (import "env" "_ZdlPv" (func $operator_delete_void*_ (type 3)))
  (import "env" "_ZNSt9bad_allocC1Ev" (func $std::bad_alloc::bad_alloc__ (type 3)))
  (import "env" "_ZNSt9bad_allocD1Ev" (func $std::bad_alloc::~bad_alloc__ (type 3)))
  (import "env" "_Znwm" (func $operator_new_unsigned_long_ (type 1)))
  (import "env" "sgx_thread_mutex_lock" (func $sgx_thread_mutex_lock (type 14)))
  (import "env" "sgx_thread_mutex_unlock" (func $sgx_thread_mutex_unlock (type 14)))
  (import "env" "sgx_thread_cond_wait" (func $sgx_thread_cond_wait (type 7)))
  (import "env" "sgx_thread_cond_signal" (func $sgx_thread_cond_signal (type 14)))
  (func $__wasm_call_ctors (type 6))
  (func $sgx_ecall_gen_credentials (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      call $ecall_gen_credentials
      local.get 1
      local.get 1
      i32.load offset=4
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_gen_credentials (type 6)
    (local i32)
    global.get $__stack_pointer
    i32.const 128
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i64.const 384
    call $malloc
    i32.store offset=120
    local.get 0
    i64.const 384
    call $malloc
    i32.store offset=112
    local.get 0
    i64.const 65537
    i64.store offset=104
    local.get 0
    i64.const 384
    call $malloc
    i32.store offset=96
    local.get 0
    i64.const 384
    call $malloc
    i32.store offset=88
    local.get 0
    i64.const 384
    call $malloc
    i32.store offset=80
    local.get 0
    i64.const 384
    call $malloc
    i32.store offset=72
    local.get 0
    i64.const 384
    call $malloc
    i32.store offset=64
    local.get 0
    i32.const 384
    i32.const 4
    local.get 0
    i32.load offset=120
    local.get 0
    i32.load offset=112
    local.get 0
    i32.const 104
    i32.add
    local.get 0
    i32.load offset=96
    local.get 0
    i32.load offset=88
    local.get 0
    i32.load offset=80
    local.get 0
    i32.load offset=72
    local.get 0
    i32.load offset=64
    call $sgx_create_rsa_key_pair
    i32.store offset=60
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load offset=60
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 0
        i32.load offset=60
        i32.store
        i32.const 2772
        local.get 0
        call $printf
        drop
        br 1 (;@1;)
      end
      local.get 0
      i32.load offset=96
      call $free
      local.get 0
      i32.load offset=88
      call $free
      local.get 0
      i32.load offset=80
      call $free
      local.get 0
      i32.load offset=72
      call $free
      local.get 0
      i32.load offset=64
      call $free
      local.get 0
      i64.const 773
      i64.store offset=48
      local.get 0
      local.get 0
      i64.load offset=48
      call $malloc
      i32.store offset=40
      local.get 0
      i32.load offset=40
      local.get 0
      i32.load offset=120
      i32.const 384
      call $memcpy
      drop
      local.get 0
      i32.load offset=40
      i32.const 384
      i32.add
      local.get 0
      i32.const 104
      i32.add
      i32.load align=1
      i32.store align=1
      local.get 0
      i32.load offset=40
      i32.const 10
      i32.store8 offset=388
      local.get 0
      i32.load offset=40
      i32.const 384
      i32.add
      i32.const 4
      i32.add
      i32.const 1
      i32.add
      local.get 0
      i32.load offset=112
      i32.const 384
      call $memcpy
      drop
      local.get 0
      i32.load offset=112
      call $free
      local.get 0
      i32.load offset=120
      call $free
      local.get 0
      i32.const 0
      local.get 0
      i64.load offset=48
      i32.wrap_i64
      call $sgx_calc_sealed_data_size
      i64.extend_i32_u
      i64.store offset=32
      local.get 0
      local.get 0
      i64.load offset=32
      call $malloc
      i32.store offset=24
      local.get 0
      i32.const 0
      i32.const 0
      local.get 0
      i64.load offset=48
      i32.wrap_i64
      local.get 0
      i32.load offset=40
      local.get 0
      i64.load offset=32
      i32.wrap_i64
      local.get 0
      i32.load offset=24
      call $sgx_seal_data
      i32.store offset=60
      local.get 0
      i32.load offset=40
      call $free
      block  ;; label = @2
        local.get 0
        i32.load offset=60
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 0
        i32.load offset=60
        i32.store offset=16
        i32.const 2815
        local.get 0
        i32.const 16
        i32.add
        call $printf
        drop
        br 1 (;@1;)
      end
      local.get 0
      i32.load offset=24
      local.get 0
      i64.load offset=32
      i32.const 2230
      call $ocall_write_file
      drop
      local.get 0
      i32.load offset=24
      call $free
    end
    local.get 0
    i32.const 128
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_unseal_and_export_pub (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i64.load offset=8
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $ecall_unseal_and_export_pub
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_unseal_and_export_pub (type 21) (param i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=56
    local.get 2
    local.get 1
    i64.store offset=48
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=56
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 2
          i64.load offset=48
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.load offset=56
      call $sgx_get_add_mac_txt_len
      i64.extend_i32_u
      i64.store offset=40
      local.get 2
      local.get 2
      i32.load offset=56
      call $sgx_get_encrypt_txt_len
      i64.extend_i32_u
      i64.store offset=32
      local.get 2
      local.get 2
      i64.load offset=32
      call $malloc
      i32.store offset=24
      local.get 2
      local.get 2
      i32.load offset=56
      i32.const 0
      local.get 2
      i32.const 40
      i32.add
      local.get 2
      i32.load offset=24
      local.get 2
      i32.const 32
      i32.add
      call $sgx_unseal_data
      i32.store offset=20
      block  ;; label = @2
        local.get 2
        i32.load offset=20
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2971
        i32.const 0
        call $printf
        drop
        br 1 (;@1;)
      end
      local.get 2
      i64.const 388
      i64.store offset=8
      local.get 2
      local.get 2
      i64.load offset=8
      call $malloc
      i32.store
      local.get 2
      i32.load
      local.get 2
      i32.load offset=24
      local.get 2
      i64.load offset=8
      i32.wrap_i64
      call $memcpy
      drop
      local.get 2
      i32.load
      local.get 2
      i64.load offset=8
      i32.const 1852
      call $ocall_write_file
      drop
    end
    local.get 2
    i32.const 64
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_run_election (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 112
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=104
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=104
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=104
          i64.const 48
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=108
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=104
      i32.store offset=96
      local.get 1
      i32.const 0
      i32.store offset=92
      local.get 1
      local.get 1
      i32.load offset=96
      i32.load
      i32.store offset=88
      local.get 1
      local.get 1
      i32.load offset=96
      i64.load offset=8
      i64.store offset=80
      local.get 1
      local.get 1
      i64.load offset=80
      i64.store offset=72
      local.get 1
      i32.const 0
      i32.store offset=64
      local.get 1
      local.get 1
      i32.load offset=96
      i32.load offset=16
      i32.store offset=56
      local.get 1
      local.get 1
      i32.load offset=96
      i64.load offset=24
      i64.store offset=48
      local.get 1
      local.get 1
      i64.load offset=48
      i64.store offset=40
      local.get 1
      i32.const 0
      i32.store offset=32
      local.get 1
      local.get 1
      i32.load offset=96
      i32.load offset=32
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=96
      i64.load offset=40
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load offset=88
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=88
        local.get 1
        i64.load offset=72
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=108
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=56
        local.get 1
        i64.load offset=40
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=108
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=108
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=72
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=72
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=92
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=72
          call $malloc
          i32.store offset=64
          block  ;; label = @4
            local.get 1
            i32.load offset=64
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=92
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=64
            local.get 1
            i64.load offset=72
            local.get 1
            i32.load offset=88
            local.get 1
            i64.load offset=72
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=92
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=40
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=40
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=92
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=40
          call $malloc
          i32.store offset=32
          block  ;; label = @4
            local.get 1
            i32.load offset=32
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=92
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=32
            local.get 1
            i64.load offset=40
            local.get 1
            i32.load offset=56
            local.get 1
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=92
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=92
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=92
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=92
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=64
        local.get 1
        i64.load offset=80
        local.get 1
        i32.load offset=32
        local.get 1
        i64.load offset=48
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $ecall_run_election
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=64
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=64
        call $free
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=32
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=32
        call $free
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=92
      i32.store offset=108
    end
    local.get 1
    i32.load offset=108
    local.set 0
    local.get 1
    i32.const 112
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_run_election (type 22) (param i32 i64 i32 i64 i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 272
    i32.sub
    local.tee 6
    global.set $__stack_pointer
    local.get 6
    local.get 0
    i32.store offset=264
    local.get 6
    local.get 1
    i64.store offset=256
    local.get 6
    local.get 2
    i32.store offset=248
    local.get 6
    local.get 3
    i64.store offset=240
    local.get 6
    local.get 4
    i32.store offset=232
    local.get 6
    local.get 5
    i64.store offset=224
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 6
          i32.load offset=264
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 6
          i64.load offset=256
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=248
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 6
          i64.load offset=240
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=232
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 6
          i64.load offset=224
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        br 1 (;@1;)
      end
      local.get 6
      local.get 6
      i64.load offset=224
      i32.wrap_i64
      i32.const 768
      i32.div_s
      i32.store offset=220
      local.get 6
      local.get 6
      i64.load offset=240
      i32.wrap_i64
      i32.const 32
      i32.div_s
      i32.store offset=216
      local.get 6
      i32.const 0
      i32.store offset=212
      local.get 6
      local.get 6
      i64.load offset=224
      i64.const 1
      i64.shr_u
      local.get 6
      i32.load offset=220
      i32.const 5
      i32.shl
      i64.extend_i32_s
      i64.sub
      i64.store offset=200
      local.get 6
      local.get 6
      i64.load offset=200
      call $malloc
      i32.store offset=192
      local.get 6
      local.get 6
      i64.load offset=200
      local.get 6
      i32.load offset=220
      i64.extend_i32_s
      i64.div_u
      i64.store offset=184
      local.get 6
      i32.load offset=192
      i32.const 0
      local.get 6
      i64.load offset=200
      i32.wrap_i64
      call $memset
      drop
      local.get 6
      local.get 6
      i32.load offset=264
      call $sgx_get_add_mac_txt_len
      i64.extend_i32_u
      i64.store offset=176
      local.get 6
      local.get 6
      i32.load offset=264
      call $sgx_get_encrypt_txt_len
      i64.extend_i32_u
      i64.store offset=168
      local.get 6
      local.get 6
      i64.load offset=168
      call $malloc
      i32.store offset=160
      local.get 6
      local.get 6
      i32.load offset=264
      i32.const 0
      local.get 6
      i32.const 176
      i32.add
      local.get 6
      i32.load offset=160
      local.get 6
      i32.const 168
      i32.add
      call $sgx_unseal_data
      i32.store offset=156
      block  ;; label = @2
        local.get 6
        i32.load offset=156
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        local.get 6
        i32.load offset=156
        i32.store
        i32.const 2855
        local.get 6
        call $printf
        drop
        br 1 (;@1;)
      end
      local.get 6
      i32.const 384
      i32.const 4
      i32.const 384
      local.get 6
      i32.load offset=160
      local.get 6
      i32.load offset=160
      i32.const 384
      i32.add
      local.get 6
      i32.load offset=160
      i32.const 384
      i32.add
      i32.const 4
      i32.add
      i32.const 1
      i32.add
      local.get 6
      i32.const 152
      i32.add
      call $sgx_create_rsa_priv1_key
      i32.store offset=156
      block  ;; label = @2
        local.get 6
        i32.load offset=156
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        local.get 6
        i32.load offset=156
        i32.store offset=16
        i32.const 2366
        local.get 6
        i32.const 16
        i32.add
        call $printf
        drop
        br 1 (;@1;)
      end
      local.get 6
      i32.const 0
      i32.store offset=148
      block  ;; label = @2
        loop  ;; label = @3
          local.get 6
          i32.load offset=148
          local.get 6
          i32.load offset=220
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 6
          i64.const 384
          i64.store offset=136
          local.get 6
          local.get 6
          i64.load offset=136
          call $malloc
          i32.store offset=128
          local.get 6
          i32.load offset=128
          i32.const 0
          i32.const 384
          call $memset
          drop
          local.get 6
          local.get 6
          i32.load offset=152
          local.get 6
          i32.load offset=128
          local.get 6
          i32.const 136
          i32.add
          local.get 6
          i32.load offset=232
          local.get 6
          i32.load offset=148
          i32.const 384
          i32.mul
          i32.const 1
          i32.shl
          i64.extend_i32_s
          i32.wrap_i64
          i32.add
          i64.const 384
          call $sgx_rsa_priv_decrypt_sha256
          i32.store offset=156
          block  ;; label = @4
            local.get 6
            i32.load offset=156
            i32.eqz
            br_if 0 (;@4;)
            i32.const 3029
            i32.const 0
            call $printf
            drop
            br 3 (;@1;)
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 6
              i32.load offset=128
              i64.const 32
              local.get 6
              i32.load offset=248
              local.get 6
              i64.load offset=240
              call $isAuthorizedVoter_unsigned_char*__unsigned_long__unsigned_char*__unsigned_long_
              br_if 0 (;@5;)
              br 1 (;@4;)
            end
            local.get 6
            i32.load offset=192
            local.get 6
            i32.load offset=212
            i64.extend_i32_s
            local.get 6
            i64.load offset=200
            local.get 6
            i32.load offset=220
            i64.extend_i32_s
            i64.div_u
            i64.mul
            i32.wrap_i64
            i32.add
            local.get 6
            i32.load offset=128
            i32.const 32
            i32.add
            local.get 6
            i64.load offset=136
            i64.const 32
            i64.sub
            i64.const 1
            i64.sub
            i32.wrap_i64
            call $memcpy
            drop
            local.get 6
            local.get 6
            i32.load offset=212
            i32.const 1
            i32.add
            i32.store offset=212
          end
          local.get 6
          local.get 6
          i32.load offset=148
          i32.const 1
          i32.add
          i32.store offset=148
          br 0 (;@3;)
        end
      end
      block  ;; label = @2
        local.get 6
        i32.load offset=212
        i32.const 1
        i32.gt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        local.get 6
        i64.load offset=184
        call $malloc
        i32.store offset=120
        local.get 6
        local.get 6
        i32.load offset=212
        i64.extend_i32_s
        call $malloc
        i32.store offset=104
        local.get 6
        local.get 6
        i32.load offset=104
        local.get 6
        i32.load offset=212
        i64.extend_i32_s
        i64.const 1
        i64.shl
        call $sgx_read_rand
        i32.store offset=156
        local.get 6
        i64.const 0
        i64.store offset=112
        block  ;; label = @3
          loop  ;; label = @4
            local.get 6
            i64.load offset=112
            local.get 6
            i32.load offset=212
            i64.extend_i32_s
            i64.lt_u
            i32.const 1
            i32.and
            i32.eqz
            br_if 1 (;@3;)
            local.get 6
            local.get 6
            i32.load offset=104
            local.get 6
            i64.load offset=112
            i32.wrap_i64
            i32.const 1
            i32.shl
            i32.add
            i32.load16_u
            i32.const 65535
            i32.and
            i64.extend_i32_u
            i64.store offset=96
            local.get 6
            local.get 6
            i64.load offset=112
            local.get 6
            i64.load offset=96
            i64.const 65535
            local.get 6
            i32.load offset=212
            i64.extend_i32_s
            local.get 6
            i64.load offset=112
            i64.sub
            i64.div_u
            i64.const 1
            i64.add
            i64.div_u
            i64.add
            i64.store offset=88
            local.get 6
            i32.load offset=120
            local.get 6
            i32.load offset=192
            local.get 6
            i64.load offset=88
            local.get 6
            i64.load offset=184
            i64.mul
            i32.wrap_i64
            i32.add
            local.get 6
            i64.load offset=184
            i32.wrap_i64
            call $memcpy
            drop
            local.get 6
            i32.load offset=192
            local.get 6
            i64.load offset=88
            local.get 6
            i64.load offset=184
            i64.mul
            i32.wrap_i64
            i32.add
            local.get 6
            i32.load offset=192
            local.get 6
            i64.load offset=112
            local.get 6
            i64.load offset=184
            i64.mul
            i32.wrap_i64
            i32.add
            local.get 6
            i64.load offset=184
            i32.wrap_i64
            call $memcpy
            drop
            local.get 6
            i32.load offset=192
            local.get 6
            i64.load offset=112
            local.get 6
            i64.load offset=184
            i64.mul
            i32.wrap_i64
            i32.add
            local.get 6
            i32.load offset=120
            local.get 6
            i64.load offset=184
            i32.wrap_i64
            call $memcpy
            drop
            local.get 6
            local.get 6
            i64.load offset=112
            i64.const 1
            i64.add
            i64.store offset=112
            br 0 (;@4;)
          end
        end
      end
      local.get 6
      local.get 6
      i32.load offset=220
      i32.store offset=48
      i32.const 2923
      local.get 6
      i32.const 48
      i32.add
      call $printf
      drop
      local.get 6
      local.get 6
      i32.load offset=216
      i32.store offset=64
      i32.const 2899
      local.get 6
      i32.const 64
      i32.add
      call $printf
      drop
      local.get 6
      local.get 6
      i32.load offset=212
      i32.store offset=80
      i32.const 2947
      local.get 6
      i32.const 80
      i32.add
      call $printf
      drop
      i32.const 3052
      i32.const 0
      call $printf
      drop
      local.get 6
      i32.const 0
      i32.store offset=84
      block  ;; label = @2
        loop  ;; label = @3
          local.get 6
          i32.load offset=84
          local.get 6
          i32.load offset=212
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 6
          local.get 6
          i32.load offset=192
          local.get 6
          i32.load offset=84
          i64.extend_i32_s
          local.get 6
          i64.load offset=184
          i64.mul
          i32.wrap_i64
          i32.add
          i32.store offset=32
          i32.const 2768
          local.get 6
          i32.const 32
          i32.add
          call $printf
          drop
          local.get 6
          local.get 6
          i32.load offset=84
          i32.const 1
          i32.add
          i32.store offset=84
          br 0 (;@3;)
        end
      end
      i32.const 3115
      i32.const 0
      call $printf
      drop
    end
    local.get 6
    i32.const 272
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_check_voter (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 144
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=136
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=136
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=136
          i64.const 64
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=140
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=136
      i32.store offset=128
      local.get 1
      i32.const 0
      i32.store offset=124
      local.get 1
      local.get 1
      i32.load offset=128
      i32.load
      i32.store offset=120
      local.get 1
      local.get 1
      i32.load offset=128
      i64.load offset=8
      i64.store offset=112
      local.get 1
      local.get 1
      i64.load offset=112
      i64.store offset=104
      local.get 1
      i32.const 0
      i32.store offset=96
      local.get 1
      local.get 1
      i32.load offset=128
      i32.load offset=16
      i32.store offset=88
      local.get 1
      local.get 1
      i32.load offset=128
      i64.load offset=24
      i64.store offset=80
      local.get 1
      local.get 1
      i64.load offset=80
      i64.store offset=72
      local.get 1
      i32.const 0
      i32.store offset=64
      local.get 1
      local.get 1
      i32.load offset=128
      i32.load offset=32
      i32.store offset=56
      local.get 1
      local.get 1
      i32.load offset=128
      i64.load offset=40
      i64.store offset=48
      local.get 1
      local.get 1
      i64.load offset=48
      i64.store offset=40
      local.get 1
      i32.const 0
      i32.store offset=32
      local.get 1
      local.get 1
      i32.load offset=128
      i32.load offset=48
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=128
      i64.load offset=56
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load offset=120
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=120
        local.get 1
        i64.load offset=104
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=140
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=88
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=88
        local.get 1
        i64.load offset=72
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=140
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=56
        local.get 1
        i64.load offset=40
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=140
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=140
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=120
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=104
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=104
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=124
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=104
          call $malloc
          i32.store offset=96
          block  ;; label = @4
            local.get 1
            i32.load offset=96
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=124
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=96
            local.get 1
            i64.load offset=104
            local.get 1
            i32.load offset=120
            local.get 1
            i64.load offset=104
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=124
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=72
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=72
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=124
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=72
          call $malloc
          i32.store offset=64
          block  ;; label = @4
            local.get 1
            i32.load offset=64
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=124
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=64
            local.get 1
            i64.load offset=72
            local.get 1
            i32.load offset=88
            local.get 1
            i64.load offset=72
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=124
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=40
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=40
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=124
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=40
          call $malloc
          i32.store offset=32
          block  ;; label = @4
            local.get 1
            i32.load offset=32
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=124
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=32
            local.get 1
            i64.load offset=40
            local.get 1
            i32.load offset=56
            local.get 1
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=124
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=124
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=124
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=124
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=96
        local.get 1
        i64.load offset=112
        local.get 1
        i32.load offset=64
        local.get 1
        i64.load offset=80
        local.get 1
        i32.load offset=32
        local.get 1
        i64.load offset=48
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $ecall_check_voter
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=96
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=96
        call $free
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=64
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=64
        call $free
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=32
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=32
        call $free
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=124
      i32.store offset=140
    end
    local.get 1
    i32.load offset=140
    local.set 0
    local.get 1
    i32.const 144
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_check_voter (type 23) (param i32 i64 i32 i64 i32 i64 i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 160
    i32.sub
    local.tee 8
    global.set $__stack_pointer
    local.get 8
    local.get 0
    i32.store offset=152
    local.get 8
    local.get 1
    i64.store offset=144
    local.get 8
    local.get 2
    i32.store offset=136
    local.get 8
    local.get 3
    i64.store offset=128
    local.get 8
    local.get 4
    i32.store offset=120
    local.get 8
    local.get 5
    i64.store offset=112
    local.get 8
    local.get 6
    i32.store offset=104
    local.get 8
    local.get 7
    i64.store offset=96
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 8
          i32.load offset=152
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 8
          i64.load offset=144
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 8
          i32.load offset=136
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 8
          i64.load offset=128
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 8
          i32.load offset=120
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 8
          i64.load offset=112
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 8
          i32.load offset=104
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 8
          i64.load offset=96
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        br 1 (;@1;)
      end
      local.get 8
      local.get 8
      i64.load offset=112
      i32.wrap_i64
      i32.const 768
      i32.div_s
      i32.store offset=92
      local.get 8
      local.get 8
      i32.load offset=152
      call $sgx_get_add_mac_txt_len
      i64.extend_i32_u
      i64.store offset=80
      local.get 8
      local.get 8
      i32.load offset=152
      call $sgx_get_encrypt_txt_len
      i64.extend_i32_u
      i64.store offset=72
      local.get 8
      local.get 8
      i64.load offset=72
      call $malloc
      i32.store offset=64
      local.get 8
      local.get 8
      i32.load offset=152
      i32.const 0
      local.get 8
      i32.const 80
      i32.add
      local.get 8
      i32.load offset=64
      local.get 8
      i32.const 72
      i32.add
      call $sgx_unseal_data
      i32.store offset=60
      block  ;; label = @2
        local.get 8
        i32.load offset=60
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        local.get 8
        i32.load offset=60
        i32.store
        i32.const 2855
        local.get 8
        call $printf
        drop
        br 1 (;@1;)
      end
      local.get 8
      i32.const 384
      i32.const 4
      i32.const 384
      local.get 8
      i32.load offset=64
      local.get 8
      i32.load offset=64
      i32.const 384
      i32.add
      local.get 8
      i32.load offset=64
      i32.const 384
      i32.add
      i32.const 4
      i32.add
      i32.const 1
      i32.add
      local.get 8
      i32.const 56
      i32.add
      call $sgx_create_rsa_priv1_key
      i32.store offset=60
      local.get 8
      i32.load offset=64
      call $free
      block  ;; label = @2
        local.get 8
        i32.load offset=60
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        local.get 8
        i32.load offset=60
        i32.store offset=16
        i32.const 2366
        local.get 8
        i32.const 16
        i32.add
        call $printf
        drop
        br 1 (;@1;)
      end
      local.get 8
      i32.const 0
      i32.store offset=52
      block  ;; label = @2
        loop  ;; label = @3
          local.get 8
          i32.load offset=52
          local.get 8
          i32.load offset=92
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 8
          i64.const 384
          i64.store offset=40
          local.get 8
          local.get 8
          i64.load offset=40
          call $malloc
          i32.store offset=32
          local.get 8
          i32.load offset=32
          i32.const 0
          i32.const 384
          call $memset
          drop
          local.get 8
          local.get 8
          i32.load offset=56
          local.get 8
          i32.load offset=32
          local.get 8
          i32.const 40
          i32.add
          local.get 8
          i32.load offset=120
          local.get 8
          i32.load offset=52
          i32.const 384
          i32.mul
          i32.const 1
          i32.shl
          i64.extend_i32_s
          i32.wrap_i64
          i32.add
          i64.const 384
          call $sgx_rsa_priv_decrypt_sha256
          i32.store offset=60
          block  ;; label = @4
            local.get 8
            i32.load offset=60
            i32.eqz
            br_if 0 (;@4;)
            i32.const 3029
            i32.const 0
            call $printf
            drop
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 8
            i32.load offset=32
            i64.const 32
            local.get 8
            i32.load offset=104
            local.get 8
            i64.load offset=96
            call $comparePublicKeys_unsigned_char*__unsigned_long__unsigned_char*__unsigned_long_
            i32.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 8
              i32.load offset=32
              i64.const 32
              local.get 8
              i32.load offset=136
              local.get 8
              i64.load offset=128
              call $isAuthorizedVoter_unsigned_char*__unsigned_long__unsigned_char*__unsigned_long_
              br_if 0 (;@5;)
              i32.const 3073
              i32.const 0
              call $printf
              drop
              br 4 (;@1;)
            end
            i32.const 3011
            i32.const 0
            call $printf
            drop
            br 3 (;@1;)
          end
          local.get 8
          local.get 8
          i32.load offset=52
          i32.const 1
          i32.add
          i32.store offset=52
          br 0 (;@3;)
        end
      end
      i32.const 2994
      i32.const 0
      call $printf
      drop
    end
    local.get 8
    i32.const 160
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_type_char (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 1
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      i32.load offset=16
      i32.load8_u
      i32.const 24
      i32.shl
      i32.const 24
      i32.shr_s
      call $ecall_type_char
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_type_char (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store8 offset=15
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load8_u offset=15
        i32.const 24
        i32.shl
        i32.const 24
        i32.shr_s
        i32.const 18
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 67
      i32.const 1980
      i32.const 2549
      call $__assert
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_type_int (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 4
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      i32.load offset=16
      i32.load
      call $ecall_type_int
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_type_int (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=12
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=12
        i32.const 1234
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 78
      i32.const 1859
      i32.const 2488
      call $__assert
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_type_float (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 4
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      i32.load offset=16
      f32.load
      call $ecall_type_float
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_type_float (type 24) (param f32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    f32.store offset=12
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        f32.load offset=12
        f32.const 0x1.348p+10 (;=1234;)
        call $almost_equal_float__float_
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 89
      i32.const 1892
      i32.const 2684
      call $__assert
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_type_double (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      i32.load offset=16
      f64.load
      call $ecall_type_double
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_type_double (type 25) (param f64)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    f64.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        f64.load offset=8
        f64.const 0x1.34a456d5cfaadp+10 (;=1234.57;)
        call $almost_equal_double__double_
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 100
      i32.const 2330
      i32.const 2647
      call $__assert
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_type_size_t (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      i32.load offset=16
      i64.load
      call $ecall_type_size_t
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_type_size_t (type 26) (param i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i64.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i64.load offset=8
        i64.const 12345678
        i64.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 111
      i32.const 1928
      i32.const 2416
      call $__assert
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_type_wchar_t (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 4
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      i32.load offset=16
      i32.load
      call $ecall_type_wchar_t
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_type_wchar_t (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=12
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=12
        i32.const 4660
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 122
      i32.const 1909
      i32.const 2465
      call $__assert
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_type_struct (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      i32.load offset=16
      local.tee 0
      i32.load
      local.get 0
      i64.load offset=8
      call $ecall_type_struct
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_type_struct (type 21) (param i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store
    local.get 2
    local.get 1
    i64.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load
        i32.const 1234
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 133
      i32.const 1874
      i32.const 2500
      call $__assert
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i64.load offset=8
        i64.const 5678
        i64.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 134
      i32.const 1874
      i32.const 2440
      call $__assert
    end
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_type_enum_union (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      local.get 1
      i32.load offset=16
      i32.load offset=4
      i32.store offset=8
      local.get 1
      i32.load offset=16
      i32.load
      local.get 1
      i32.load offset=8
      call $ecall_type_enum_union
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_type_enum_union (type 19) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    block  ;; label = @1
      local.get 2
      i32.load offset=8
      i64.const 8
      call $sgx_is_outside_enclave
      i32.const 1
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 2
    i32.load offset=8
    i32.const 1
    i32.store
    local.get 2
    i32.load offset=8
    i32.const 2
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=12
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2098
      i32.const 151
      i32.const 2176
      i32.const 2606
      call $__assert
    end
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_pointer_user_check (type 14) (param i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 24
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      local.get 1
      i32.load offset=16
      i32.load offset=8
      i32.store offset=8
      local.get 1
      i32.load offset=8
      local.get 1
      i32.load offset=16
      i64.load offset=16
      call $ecall_pointer_user_check
      local.set 2
      local.get 1
      i32.load offset=16
      local.get 2
      i64.store
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_user_check (type 11) (param i32 i64) (result i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 176
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=172
    local.get 2
    local.get 0
    i32.store offset=56
    local.get 2
    local.get 1
    i64.store offset=48
    block  ;; label = @1
      local.get 2
      i32.load offset=56
      local.get 2
      i64.load offset=48
      call $sgx_is_outside_enclave
      i32.const 1
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 2
    i32.const 64
    i32.add
    i32.const 0
    i32.const 100
    call $memset
    drop
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i64.load offset=48
        i64.const 100
        i64.gt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        i64.const 100
        local.set 1
        br 1 (;@1;)
      end
      local.get 2
      i64.load offset=48
      local.set 1
    end
    local.get 2
    local.get 1
    i64.store offset=40
    local.get 2
    i32.const 64
    i32.add
    local.get 2
    i32.load offset=56
    local.get 2
    i64.load offset=40
    i32.wrap_i64
    call $memcpy
    drop
    local.get 2
    local.get 2
    i32.const 64
    i32.add
    local.get 2
    i64.load offset=40
    call $checksum_internal_char*__unsigned_long_
    i32.store offset=36
    local.get 2
    i32.load offset=56
    local.set 0
    local.get 2
    i64.load offset=40
    local.set 1
    local.get 2
    i32.const 16
    i32.add
    local.get 2
    i32.load offset=36
    i32.store
    local.get 2
    local.get 1
    i64.store offset=8
    local.get 2
    local.get 0
    i32.store
    i32.const 2740
    local.get 2
    call $printf
    drop
    local.get 2
    i32.load offset=56
    local.set 0
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i64.load offset=40
        i64.const 12
        i64.gt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        i64.const 12
        local.set 1
        br 1 (;@1;)
      end
      local.get 2
      i64.load offset=40
      local.set 1
    end
    local.get 0
    i32.const 2392
    local.get 1
    i32.wrap_i64
    call $memcpy
    drop
    local.get 2
    i64.load offset=40
    local.set 1
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=172
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 176
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_ecall_pointer_in (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      i64.const 4
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          i32.store offset=8
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=8
        call $ecall_pointer_in
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_in (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    block  ;; label = @1
      local.get 1
      i32.load offset=8
      i64.const 4
      call $sgx_is_within_enclave
      i32.const 1
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.load
        i32.const 1
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2063
      i32.const 101
      i32.const 2213
      i32.const 2584
      call $__assert
    end
    local.get 1
    i32.load offset=8
    i32.const 1234
    i32.store
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_pointer_out (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      i64.const 4
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          local.tee 0
          i32.store offset=8
          block  ;; label = @4
            local.get 0
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=8
          i32.const 0
          local.get 1
          i64.load offset=16
          i32.wrap_i64
          call $memset
          drop
        end
        local.get 1
        i32.load offset=8
        call $ecall_pointer_out
        block  ;; label = @3
          local.get 1
          i32.load offset=8
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_out (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    block  ;; label = @1
      local.get 1
      i32.load offset=8
      i64.const 4
      call $sgx_is_within_enclave
      i32.const 1
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.load
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2063
      i32.const 112
      i32.const 1794
      i32.const 2625
      call $__assert
    end
    local.get 1
    i32.load offset=8
    i32.const 1234
    i32.store
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_pointer_in_out (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      i64.const 4
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          i32.store offset=8
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=8
        call $ecall_pointer_in_out
        block  ;; label = @3
          local.get 1
          i32.load offset=8
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_in_out (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    block  ;; label = @1
      local.get 1
      i32.load offset=8
      i64.const 4
      call $sgx_is_within_enclave
      i32.const 1
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.load
        i32.const 1
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2063
      i32.const 123
      i32.const 1831
      i32.const 2584
      call $__assert
    end
    local.get 1
    i32.load offset=8
    i32.const 1234
    i32.store
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_pointer_string (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i64.load offset=8
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          i32.store offset=8
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=8
          local.get 1
          i64.load offset=16
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=8
            call $strlen
            i64.const 1
            i64.add
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=8
        call $ecall_pointer_string
        block  ;; label = @3
          local.get 1
          i32.load offset=8
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=8
          local.get 1
          i64.load offset=16
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          local.get 1
          local.get 1
          i32.load offset=8
          call $strlen
          i64.const 1
          i64.add
          i64.store offset=16
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_string (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.load offset=8
    i32.const 2573
    local.get 1
    i32.load offset=8
    call $strlen
    call $strncpy
    drop
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_pointer_string_const (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i64.load offset=8
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          i32.store offset=8
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=8
          local.get 1
          i64.load offset=16
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=8
            call $strlen
            i64.const 1
            i64.add
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=8
        call $ecall_pointer_string_const
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_string_const (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    local.get 1
    i32.load offset=8
    call $strlen
    call $operator_new___unsigned_long_
    i32.store
    local.get 1
    i32.load
    local.get 1
    i32.load offset=8
    local.get 1
    i32.load offset=8
    call $strlen
    call $strncpy
    drop
    block  ;; label = @1
      local.get 1
      i32.load
      local.tee 0
      i32.const 0
      i32.eq
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      local.get 0
      call $operator_delete___void*_
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_pointer_size (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i64.load offset=8
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $ecall_pointer_size
        block  ;; label = @3
          local.get 1
          i32.load
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_size (type 21) (param i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=8
    local.get 2
    local.get 1
    i64.store
    local.get 2
    i32.load offset=8
    i32.const 2573
    local.get 2
    i64.load
    call $strncpy
    drop
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_pointer_count (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i64.load offset=8
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      i64.const 2
      i64.shl
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i64.load offset=16
        i64.const 4611686018427387903
        i64.gt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $ecall_pointer_count
        block  ;; label = @3
          local.get 1
          i32.load
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_count (type 21) (param i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 2
    local.get 0
    i32.store offset=24
    local.get 2
    local.get 1
    i64.store offset=16
    local.get 2
    local.get 2
    i64.load offset=16
    i32.wrap_i64
    i32.store offset=12
    local.get 2
    local.get 2
    i32.load offset=12
    i32.const 1
    i32.sub
    i32.store offset=8
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i32.load offset=8
        i32.const 0
        i32.ge_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i32.load offset=24
        local.get 2
        i32.load offset=8
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        local.get 2
        i32.load offset=12
        i32.const 1
        i32.sub
        local.get 2
        i32.load offset=8
        i32.sub
        i32.store
        local.get 2
        local.get 2
        i32.load offset=8
        i32.const -1
        i32.add
        i32.store offset=8
        br 0 (;@2;)
      end
    end)
  (func $sgx_ecall_pointer_isptr_readonly (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i64.load offset=8
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=8
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          i32.store
          block  ;; label = @4
            local.get 1
            i32.load
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $ecall_pointer_isptr_readonly
      end
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_pointer_isptr_readonly (type 21) (param i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=8
    local.get 2
    local.get 1
    i64.store
    local.get 2
    i32.load offset=8
    i32.const 2573
    local.get 2
    i64.load
    call $strncpy
    drop
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ocall_pointer_attr (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      call $ocall_pointer_attr
      local.get 1
      local.get 1
      i32.load offset=4
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ocall_pointer_attr (type 6)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i32.const 1
    i32.store offset=12
    local.get 0
    i32.const 0
    i32.store offset=8
    local.get 0
    local.get 0
    i32.const 8
    i32.add
    call $ocall_pointer_user_check
    i32.store offset=12
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 0
    i32.const 0
    i32.store offset=8
    local.get 0
    local.get 0
    i32.const 8
    i32.add
    call $ocall_pointer_in
    i32.store offset=12
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2063
      i32.const 143
      i32.const 1946
      i32.const 2626
      call $__assert
    end
    local.get 0
    i32.const 0
    i32.store offset=8
    local.get 0
    local.get 0
    i32.const 8
    i32.add
    call $ocall_pointer_out
    i32.store offset=12
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        i32.const 1234
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2063
      i32.const 149
      i32.const 1946
      i32.const 2488
      call $__assert
    end
    local.get 0
    i32.const 0
    i32.store offset=8
    local.get 0
    local.get 0
    i32.const 8
    i32.add
    call $ocall_pointer_in_out
    i32.store offset=12
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        i32.const 1234
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2063
      i32.const 155
      i32.const 1946
      i32.const 2488
      call $__assert
    end
    local.get 0
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_array_user_check (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      local.get 1
      local.get 1
      i32.load offset=16
      i32.load
      i32.store offset=8
      local.get 1
      i32.load offset=8
      call $ecall_array_user_check
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_array_user_check (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    block  ;; label = @1
      local.get 1
      i32.load offset=8
      i64.const 16
      call $sgx_is_outside_enclave
      i32.const 1
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 1
        i32.load offset=4
        i32.const 4
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i32.load offset=4
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            i32.load
            local.get 1
            i32.load offset=4
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            br 1 (;@3;)
          end
          i32.const 2030
          i32.const 47
          i32.const 2242
          i32.const 2265
          call $__assert
        end
        local.get 1
        i32.load offset=8
        local.get 1
        i32.load offset=4
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        i32.const 3
        local.get 1
        i32.load offset=4
        i32.sub
        i32.store
        local.get 1
        local.get 1
        i32.load offset=4
        i32.const 1
        i32.add
        i32.store offset=4
        br 0 (;@2;)
      end
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_array_in (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      i64.const 16
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          i32.store offset=8
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=8
        call $ecall_array_in
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_array_in (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 1
        i32.load offset=4
        i32.const 4
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i32.load offset=4
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            i32.load
            local.get 1
            i32.load offset=4
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            br 1 (;@3;)
          end
          i32.const 2030
          i32.const 59
          i32.const 2198
          i32.const 2265
          call $__assert
        end
        local.get 1
        i32.load offset=8
        local.get 1
        i32.load offset=4
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        i32.const 3
        local.get 1
        i32.load offset=4
        i32.sub
        i32.store
        local.get 1
        local.get 1
        i32.load offset=4
        i32.const 1
        i32.add
        i32.store offset=4
        br 0 (;@2;)
      end
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_array_out (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      i64.const 16
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          local.tee 0
          i32.store offset=8
          block  ;; label = @4
            local.get 0
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=8
          i32.const 0
          local.get 1
          i64.load offset=16
          i32.wrap_i64
          call $memset
          drop
        end
        local.get 1
        i32.load offset=8
        call $ecall_array_out
        block  ;; label = @3
          local.get 1
          i32.load offset=8
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_array_out (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 1
        i32.load offset=4
        i32.const 4
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i32.load offset=4
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            i32.load
            br_if 0 (;@4;)
            br 1 (;@3;)
          end
          i32.const 2030
          i32.const 72
          i32.const 1778
          i32.const 2635
          call $__assert
        end
        local.get 1
        i32.load offset=8
        local.get 1
        i32.load offset=4
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        i32.const 3
        local.get 1
        i32.load offset=4
        i32.sub
        i32.store
        local.get 1
        local.get 1
        i32.load offset=4
        i32.const 1
        i32.add
        i32.store offset=4
        br 0 (;@2;)
      end
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_array_in_out (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      i64.const 16
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          i32.store offset=8
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=8
        call $ecall_array_in_out
        block  ;; label = @3
          local.get 1
          i32.load offset=8
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_array_in_out (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 1
        i32.load offset=4
        i32.const 4
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i32.load offset=4
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            i32.load
            local.get 1
            i32.load offset=4
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            br 1 (;@3;)
          end
          i32.const 2030
          i32.const 84
          i32.const 1812
          i32.const 2265
          call $__assert
        end
        local.get 1
        i32.load offset=8
        local.get 1
        i32.load offset=4
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        i32.const 3
        local.get 1
        i32.load offset=4
        i32.sub
        i32.store
        local.get 1
        local.get 1
        i32.load offset=4
        i32.const 1
        i32.add
        i32.store offset=4
        br 0 (;@2;)
      end
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_array_isary (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=16
          i32.load
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=16
          i32.load
          local.set 0
          br 1 (;@2;)
        end
        i32.const 0
        local.set 0
      end
      local.get 0
      call $ecall_array_isary
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_array_isary (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    block  ;; label = @1
      local.get 1
      i32.load offset=8
      i64.const 40
      call $sgx_is_outside_enclave
      i32.const 1
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 1
    i32.const 10
    i32.store offset=4
    local.get 1
    i32.const 0
    i32.store
    block  ;; label = @1
      loop  ;; label = @2
        local.get 1
        i32.load
        local.get 1
        i32.load offset=4
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i32.load
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            i32.load
            local.get 1
            i32.load
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            br 1 (;@3;)
          end
          i32.const 2030
          i32.const 99
          i32.const 1760
          i32.const 2265
          call $__assert
        end
        local.get 1
        i32.load offset=8
        local.get 1
        i32.load
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        local.get 1
        i32.load offset=4
        i32.const 1
        i32.sub
        local.get 1
        i32.load
        i32.sub
        i32.store
        local.get 1
        local.get 1
        i32.load
        i32.const 1
        i32.add
        i32.store
        br 0 (;@2;)
      end
    end
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_function_public (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      call $ecall_function_public
      local.get 1
      local.get 1
      i32.load offset=4
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_function_public (type 6)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i32.const 1
    i32.store offset=12
    local.get 0
    call $ocall_function_allow
    i32.store offset=12
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 0
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_function_private (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 4
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      call $ecall_function_private
      local.set 0
      local.get 1
      i32.load offset=16
      local.get 0
      i32.store
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_function_private (type 27) (result i32)
    i32.const 1)
  (func $sgx_ecall_malloc_free (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      call $ecall_malloc_free
      local.get 1
      local.get 1
      i32.load offset=4
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_malloc_free (type 6)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i64.const 100
    call $malloc
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2130
      i32.const 46
      i32.const 2348
      i32.const 2404
      call $__assert
    end
    local.get 0
    i32.load offset=8
    i32.const 0
    i32.const 100
    call $memset
    drop
    local.get 0
    i32.load offset=8
    call $free
    local.get 0
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_sgx_cpuid (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          i64.const 16
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=40
      i32.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=28
      local.get 1
      local.get 1
      i32.load offset=32
      i32.load
      i32.store offset=24
      local.get 1
      i64.const 16
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=24
        local.get 1
        i64.load offset=16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=16
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i64.load offset=16
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 2
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=16
          call $malloc
          local.tee 0
          i32.store offset=8
          block  ;; label = @4
            local.get 0
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=28
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=8
          i32.const 0
          local.get 1
          i64.load offset=16
          i32.wrap_i64
          call $memset
          drop
        end
        local.get 1
        i32.load offset=8
        local.get 1
        i32.load offset=32
        i32.load offset=4
        call $ecall_sgx_cpuid
        block  ;; label = @3
          local.get 1
          i32.load offset=8
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=28
            br 2 (;@2;)
          end
        end
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
      end
      local.get 1
      local.get 1
      i32.load offset=28
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_sgx_cpuid (type 19) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=8
    local.get 2
    local.get 1
    i32.store offset=4
    local.get 2
    local.get 2
    i32.load offset=8
    local.get 2
    i32.load offset=4
    call $sgx_cpuid
    i32.store
    block  ;; label = @1
      local.get 2
      i32.load
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_exception (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      call $ecall_exception
      local.get 1
      local.get 1
      i32.load offset=4
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_exception (type 6)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 304
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    local.get 0
    i32.const 32
    i32.add
    i32.store offset=64
    local.get 0
    i32.const 2172
    i32.store offset=56
    local.get 0
    local.get 0
    i32.load offset=64
    local.tee 1
    i32.store offset=120
    local.get 0
    local.get 0
    i32.load offset=120
    i32.store offset=128
    local.get 0
    local.get 0
    i32.load offset=128
    local.tee 2
    i32.store offset=136
    local.get 2
    i64.const 0
    i64.store
    local.get 2
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 2
    i32.const 8
    i32.add
    i64.const 0
    i64.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 2290
      i32.const 2062
      i32.const 2277
      i32.const 1965
      call $__assert
    end
    local.get 1
    local.get 0
    i32.load offset=56
    local.get 0
    i32.load offset=56
    call $std::__1::char_traits<char>::length_char_const*_
    call $std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>::__init_char_const*__unsigned_long_
    i64.const 16
    call $__cxa_allocate_exception
    local.tee 2
    local.get 0
    i32.const 32
    i32.add
    call $std::runtime_error::runtime_error_std::__1::basic_string<char__std::__1::char_traits<char>__std::__1::allocator<char>_>_const&_
    local.get 2
    i32.const 0
    i32.const 1
    call $__cxa_throw
    unreachable)
  (func $sgx_ecall_map (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      call $ecall_map
      local.get 1
      local.get 1
      i32.load offset=4
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_map (type 6)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 1248
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    local.get 0
    i32.const 184
    i32.add
    i32.store offset=208
    local.get 0
    i32.load offset=208
    local.set 1
    local.get 0
    local.get 0
    i32.const 200
    i32.add
    i32.store offset=576
    local.get 1
    local.get 0
    i32.const 200
    i32.add
    call $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__tree_std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>_const&_
    local.get 0
    i32.const 97
    i32.store8 offset=175
    local.get 0
    i32.const 1
    i32.store offset=168
    local.get 0
    local.get 0
    i32.const 176
    i32.add
    i32.store offset=424
    local.get 0
    local.get 0
    i32.const 175
    i32.add
    i32.store offset=416
    local.get 0
    local.get 0
    i32.const 168
    i32.add
    i32.store offset=408
    local.get 0
    i32.load offset=424
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=416
    i32.store offset=608
    local.get 1
    local.get 0
    i32.load offset=608
    i32.load8_u
    i32.store8
    local.get 0
    local.get 0
    i32.load offset=408
    i32.store offset=640
    local.get 1
    local.get 0
    i32.load offset=640
    i32.load
    i32.store offset=4
    local.get 0
    local.get 0
    i32.const 184
    i32.add
    i32.store offset=384
    local.get 0
    local.get 0
    i32.const 176
    i32.add
    i32.store offset=376
    local.get 0
    i32.load offset=384
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=376
    i32.store offset=808
    local.get 0
    i32.load offset=808
    local.set 2
    local.get 0
    local.get 1
    i32.store offset=656
    local.get 0
    local.get 2
    i32.store offset=648
    local.get 0
    i32.load offset=656
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=648
    i32.store offset=992
    local.get 0
    i32.load offset=992
    local.set 2
    local.get 0
    local.get 0
    i32.load offset=648
    i32.store offset=800
    local.get 0
    i32.const 24
    i32.add
    local.get 1
    local.get 2
    local.get 0
    i32.load offset=800
    call $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::pair<char_const__int>_>_char_const&__std::__1::pair<char_const__int>&&_
    local.get 0
    i32.load8_u offset=28
    local.set 1
    local.get 0
    i32.load offset=24
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=664
    local.get 0
    local.get 1
    i32.store8 offset=668
    local.get 0
    i32.load8_u offset=668
    local.set 1
    local.get 0
    i32.load offset=664
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=360
    local.get 0
    local.get 1
    i32.store8 offset=364
    local.get 0
    local.get 0
    i32.const 392
    i32.add
    i32.store offset=864
    local.get 0
    local.get 0
    i32.const 360
    i32.add
    i32.store offset=856
    local.get 0
    i32.const 0
    i32.store offset=848
    local.get 0
    i32.load offset=864
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=856
    i32.store offset=1024
    local.get 0
    local.get 0
    i32.load offset=1024
    i64.load
    i64.store offset=840
    local.get 0
    local.get 0
    i32.load offset=840
    i32.store offset=1088
    local.get 0
    local.get 1
    i32.store offset=1080
    local.get 0
    i32.load offset=1080
    local.get 0
    i64.load offset=1088
    i64.store
    local.get 0
    local.get 0
    i32.load offset=856
    i32.const 4
    i32.add
    i32.store offset=1152
    local.get 1
    local.get 0
    i32.load offset=1152
    i32.load8_u
    i32.const 1
    i32.and
    i32.store8 offset=4
    local.get 0
    i32.load8_u offset=396
    local.set 1
    local.get 0
    i32.load offset=392
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=144
    local.get 0
    local.get 1
    i32.store8 offset=148
    local.get 0
    i32.const 98
    i32.store8 offset=135
    local.get 0
    i32.const 2
    i32.store offset=128
    local.get 0
    local.get 0
    i32.const 136
    i32.add
    i32.store offset=448
    local.get 0
    local.get 0
    i32.const 135
    i32.add
    i32.store offset=440
    local.get 0
    local.get 0
    i32.const 128
    i32.add
    i32.store offset=432
    local.get 0
    i32.load offset=448
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=440
    i32.store offset=600
    local.get 1
    local.get 0
    i32.load offset=600
    i32.load8_u
    i32.store8
    local.get 0
    local.get 0
    i32.load offset=432
    i32.store offset=632
    local.get 1
    local.get 0
    i32.load offset=632
    i32.load
    i32.store offset=4
    local.get 0
    local.get 0
    i32.const 184
    i32.add
    i32.store offset=336
    local.get 0
    local.get 0
    i32.const 136
    i32.add
    i32.store offset=328
    local.get 0
    i32.load offset=336
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=328
    i32.store offset=816
    local.get 0
    i32.load offset=816
    local.set 2
    local.get 0
    local.get 1
    i32.store offset=688
    local.get 0
    local.get 2
    i32.store offset=680
    local.get 0
    i32.load offset=688
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=680
    i32.store offset=984
    local.get 0
    i32.load offset=984
    local.set 2
    local.get 0
    local.get 0
    i32.load offset=680
    i32.store offset=792
    local.get 0
    i32.const 16
    i32.add
    local.get 1
    local.get 2
    local.get 0
    i32.load offset=792
    call $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::pair<char_const__int>_>_char_const&__std::__1::pair<char_const__int>&&_
    local.get 0
    i32.load8_u offset=20
    local.set 1
    local.get 0
    i32.load offset=16
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=696
    local.get 0
    local.get 1
    i32.store8 offset=700
    local.get 0
    i32.load8_u offset=700
    local.set 1
    local.get 0
    i32.load offset=696
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=312
    local.get 0
    local.get 1
    i32.store8 offset=316
    local.get 0
    local.get 0
    i32.const 344
    i32.add
    i32.store offset=896
    local.get 0
    local.get 0
    i32.const 312
    i32.add
    i32.store offset=888
    local.get 0
    i32.const 0
    i32.store offset=880
    local.get 0
    i32.load offset=896
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=888
    i32.store offset=1016
    local.get 0
    local.get 0
    i32.load offset=1016
    i64.load
    i64.store offset=872
    local.get 0
    local.get 0
    i32.load offset=872
    i32.store offset=1072
    local.get 0
    local.get 1
    i32.store offset=1064
    local.get 0
    i32.load offset=1064
    local.get 0
    i64.load offset=1072
    i64.store
    local.get 0
    local.get 0
    i32.load offset=888
    i32.const 4
    i32.add
    i32.store offset=1144
    local.get 1
    local.get 0
    i32.load offset=1144
    i32.load8_u
    i32.const 1
    i32.and
    i32.store8 offset=4
    local.get 0
    i32.load8_u offset=348
    local.set 1
    local.get 0
    i32.load offset=344
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=112
    local.get 0
    local.get 1
    i32.store8 offset=116
    local.get 0
    i32.const 99
    i32.store8 offset=103
    local.get 0
    i32.const 3
    i32.store offset=96
    local.get 0
    local.get 0
    i32.const 104
    i32.add
    i32.store offset=472
    local.get 0
    local.get 0
    i32.const 103
    i32.add
    i32.store offset=464
    local.get 0
    local.get 0
    i32.const 96
    i32.add
    i32.store offset=456
    local.get 0
    i32.load offset=472
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=464
    i32.store offset=592
    local.get 1
    local.get 0
    i32.load offset=592
    i32.load8_u
    i32.store8
    local.get 0
    local.get 0
    i32.load offset=456
    i32.store offset=624
    local.get 1
    local.get 0
    i32.load offset=624
    i32.load
    i32.store offset=4
    local.get 0
    local.get 0
    i32.const 184
    i32.add
    i32.store offset=288
    local.get 0
    local.get 0
    i32.const 104
    i32.add
    i32.store offset=280
    local.get 0
    i32.load offset=288
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=280
    i32.store offset=824
    local.get 0
    i32.load offset=824
    local.set 2
    local.get 0
    local.get 1
    i32.store offset=720
    local.get 0
    local.get 2
    i32.store offset=712
    local.get 0
    i32.load offset=720
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=712
    i32.store offset=976
    local.get 0
    i32.load offset=976
    local.set 2
    local.get 0
    local.get 0
    i32.load offset=712
    i32.store offset=784
    local.get 0
    i32.const 8
    i32.add
    local.get 1
    local.get 2
    local.get 0
    i32.load offset=784
    call $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::pair<char_const__int>_>_char_const&__std::__1::pair<char_const__int>&&_
    local.get 0
    i32.load8_u offset=12
    local.set 1
    local.get 0
    i32.load offset=8
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=728
    local.get 0
    local.get 1
    i32.store8 offset=732
    local.get 0
    i32.load8_u offset=732
    local.set 1
    local.get 0
    i32.load offset=728
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=264
    local.get 0
    local.get 1
    i32.store8 offset=268
    local.get 0
    local.get 0
    i32.const 296
    i32.add
    i32.store offset=928
    local.get 0
    local.get 0
    i32.const 264
    i32.add
    i32.store offset=920
    local.get 0
    i32.const 0
    i32.store offset=912
    local.get 0
    i32.load offset=928
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=920
    i32.store offset=1008
    local.get 0
    local.get 0
    i32.load offset=1008
    i64.load
    i64.store offset=904
    local.get 0
    local.get 0
    i32.load offset=904
    i32.store offset=1056
    local.get 0
    local.get 1
    i32.store offset=1048
    local.get 0
    i32.load offset=1048
    local.get 0
    i64.load offset=1056
    i64.store
    local.get 0
    local.get 0
    i32.load offset=920
    i32.const 4
    i32.add
    i32.store offset=1136
    local.get 1
    local.get 0
    i32.load offset=1136
    i32.load8_u
    i32.const 1
    i32.and
    i32.store8 offset=4
    local.get 0
    i32.load8_u offset=300
    local.set 1
    local.get 0
    i32.load offset=296
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=80
    local.get 0
    local.get 1
    i32.store8 offset=84
    local.get 0
    i32.const 100
    i32.store8 offset=71
    local.get 0
    i32.const 4
    i32.store offset=64
    local.get 0
    local.get 0
    i32.const 72
    i32.add
    i32.store offset=496
    local.get 0
    local.get 0
    i32.const 71
    i32.add
    i32.store offset=488
    local.get 0
    local.get 0
    i32.const 64
    i32.add
    i32.store offset=480
    local.get 0
    i32.load offset=496
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=488
    i32.store offset=584
    local.get 1
    local.get 0
    i32.load offset=584
    i32.load8_u
    i32.store8
    local.get 0
    local.get 0
    i32.load offset=480
    i32.store offset=616
    local.get 1
    local.get 0
    i32.load offset=616
    i32.load
    i32.store offset=4
    local.get 0
    local.get 0
    i32.const 184
    i32.add
    i32.store offset=240
    local.get 0
    local.get 0
    i32.const 72
    i32.add
    i32.store offset=232
    local.get 0
    i32.load offset=240
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=232
    i32.store offset=832
    local.get 0
    i32.load offset=832
    local.set 2
    local.get 0
    local.get 1
    i32.store offset=752
    local.get 0
    local.get 2
    i32.store offset=744
    local.get 0
    i32.load offset=752
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=744
    i32.store offset=968
    local.get 0
    i32.load offset=968
    local.set 2
    local.get 0
    local.get 0
    i32.load offset=744
    i32.store offset=776
    local.get 0
    local.get 1
    local.get 2
    local.get 0
    i32.load offset=776
    call $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::pair<char_const__int>_>_char_const&__std::__1::pair<char_const__int>&&_
    local.get 0
    i32.load8_u offset=4
    local.set 1
    local.get 0
    i32.load
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=760
    local.get 0
    local.get 1
    i32.store8 offset=764
    local.get 0
    i32.load8_u offset=764
    local.set 1
    local.get 0
    i32.load offset=760
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=216
    local.get 0
    local.get 1
    i32.store8 offset=220
    local.get 0
    local.get 0
    i32.const 248
    i32.add
    i32.store offset=960
    local.get 0
    local.get 0
    i32.const 216
    i32.add
    i32.store offset=952
    local.get 0
    i32.const 0
    i32.store offset=944
    local.get 0
    i32.load offset=960
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=952
    i32.store offset=1000
    local.get 0
    local.get 0
    i32.load offset=1000
    i64.load
    i64.store offset=936
    local.get 0
    local.get 0
    i32.load offset=936
    i32.store offset=1040
    local.get 0
    local.get 1
    i32.store offset=1032
    local.get 0
    i32.load offset=1032
    local.get 0
    i64.load offset=1040
    i64.store
    local.get 0
    local.get 0
    i32.load offset=952
    i32.const 4
    i32.add
    i32.store offset=1128
    local.get 1
    local.get 0
    i32.load offset=1128
    i32.load8_u
    i32.const 1
    i32.and
    i32.store8 offset=4
    local.get 0
    i32.load8_u offset=252
    local.set 1
    local.get 0
    i32.load offset=248
    local.set 2
    local.get 0
    local.get 2
    i32.store offset=48
    local.get 0
    local.get 1
    i32.store8 offset=52
    local.get 0
    i32.const 97
    i32.store8 offset=47
    local.get 0
    i32.const 184
    i32.add
    local.get 0
    i32.const 47
    i32.add
    call $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::operator___char&&_
    local.set 1
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 1
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 1996
      i32.const 81
      i32.const 2162
      i32.const 2594
      call $__assert
    end
    local.get 0
    i32.const 98
    i32.store8 offset=46
    local.get 0
    i32.const 184
    i32.add
    local.get 0
    i32.const 46
    i32.add
    call $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::operator___char&&_
    local.set 1
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 2
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 1996
      i32.const 82
      i32.const 2162
      i32.const 2561
      call $__assert
    end
    local.get 0
    i32.const 99
    i32.store8 offset=45
    local.get 0
    i32.const 184
    i32.add
    local.get 0
    i32.const 45
    i32.add
    call $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::operator___char&&_
    local.set 1
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 3
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 1996
      i32.const 83
      i32.const 2162
      i32.const 2537
      call $__assert
    end
    local.get 0
    i32.const 100
    i32.store8 offset=44
    local.get 0
    i32.const 184
    i32.add
    local.get 0
    i32.const 44
    i32.add
    call $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::operator___char&&_
    local.set 1
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 4
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 1996
      i32.const 84
      i32.const 2162
      i32.const 2525
      call $__assert
    end
    local.get 0
    i32.const 101
    i32.store8 offset=39
    local.get 0
    local.get 0
    i32.const 184
    i32.add
    i32.store offset=536
    local.get 0
    local.get 0
    i32.const 39
    i32.add
    i32.store offset=528
    local.get 0
    i32.load offset=536
    local.get 0
    i32.load offset=528
    call $std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::find<char>_char_const&_
    local.set 1
    local.get 0
    local.get 1
    i32.store offset=520
    local.get 0
    local.get 0
    i32.load offset=520
    i32.store offset=1120
    local.get 0
    local.get 0
    i32.const 544
    i32.add
    i32.store offset=1112
    local.get 0
    i32.load offset=1112
    local.get 0
    i32.const 1120
    i32.add
    i64.load
    i64.store
    local.get 0
    i32.load offset=544
    local.set 1
    local.get 0
    local.get 1
    i32.store offset=40
    local.get 0
    local.get 0
    i32.const 184
    i32.add
    i32.store offset=560
    local.get 0
    local.get 0
    i32.load offset=560
    i32.store offset=1160
    local.get 0
    local.get 0
    i32.load offset=1160
    i32.store offset=1176
    local.get 0
    local.get 0
    i32.load offset=1176
    i32.const 4
    i32.add
    i32.store offset=1200
    local.get 0
    local.get 0
    i32.load offset=1200
    i32.store offset=1208
    local.get 0
    local.get 0
    i32.load offset=1208
    i32.store offset=1184
    local.get 0
    local.get 0
    i32.load offset=1184
    i32.store offset=1192
    local.get 0
    i32.load offset=1192
    local.set 1
    local.get 0
    local.get 0
    i32.const 1168
    i32.add
    i32.store offset=1224
    local.get 0
    local.get 1
    i32.store offset=1216
    local.get 0
    i32.load offset=1224
    local.get 0
    i32.load offset=1216
    i32.store
    local.get 0
    local.get 0
    i32.load offset=1168
    i32.store offset=552
    local.get 0
    local.get 0
    i32.load offset=552
    i32.store offset=1104
    local.get 0
    local.get 0
    i32.const 568
    i32.add
    i32.store offset=1096
    local.get 0
    i32.load offset=1096
    local.get 0
    i32.const 1104
    i32.add
    i64.load
    i64.store
    local.get 0
    local.get 0
    i32.load offset=568
    i32.store offset=32
    local.get 0
    local.get 0
    i32.const 40
    i32.add
    i32.store offset=512
    local.get 0
    local.get 0
    i32.const 32
    i32.add
    i32.store offset=504
    local.get 0
    i32.load offset=504
    local.set 1
    local.get 0
    local.get 0
    i32.load offset=512
    i32.store offset=1240
    local.get 0
    local.get 1
    i32.store offset=1232
    local.get 0
    i32.load offset=1240
    i32.load
    local.get 0
    i32.load offset=1232
    i32.load
    i32.eq
    local.set 1
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 1996
      i32.const 86
      i32.const 2162
      i32.const 2717
      call $__assert
    end
    local.get 0
    i32.const 184
    i32.add
    call $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::~map__
    local.get 0
    i32.const 1248
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_increase_counter (type 14) (param i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=24
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=24
          i64.const 8
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=24
      i32.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=12
      call $ecall_increase_counter
      local.set 2
      local.get 1
      i32.load offset=16
      local.get 2
      i64.store
      local.get 1
      local.get 1
      i32.load offset=12
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_increase_counter (type 28) (result i64)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i64.const 0
    i64.store offset=24
    local.get 0
    i32.const 0
    i32.store offset=20
    block  ;; label = @1
      loop  ;; label = @2
        local.get 0
        i32.load offset=20
        i32.const 500
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        i32.const 3120
        call $sgx_thread_mutex_lock
        drop
        local.get 0
        i32.const 0
        i64.load offset=3464
        i64.store offset=8
        local.get 0
        local.get 0
        i64.load offset=8
        i64.const 1
        i64.add
        local.tee 1
        i64.store offset=8
        i32.const 0
        local.get 1
        i64.store offset=3464
        block  ;; label = @3
          i64.const 2000
          i32.const 0
          i64.load offset=3464
          i64.eq
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i32.const 0
          i64.load offset=3464
          i64.store offset=24
        end
        i32.const 3120
        call $sgx_thread_mutex_unlock
        drop
        local.get 0
        local.get 0
        i32.load offset=20
        i32.const 1
        i32.add
        i32.store offset=20
        br 0 (;@2;)
      end
    end
    local.get 0
    i64.load offset=24
    local.set 1
    local.get 0
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_ecall_producer (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      call $ecall_producer
      local.get 1
      local.get 1
      i32.load offset=4
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_producer (type 6)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i32.const 0
    i32.store offset=12
    block  ;; label = @1
      loop  ;; label = @2
        local.get 0
        i32.load offset=12
        i32.const 2000
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 0
        i32.const 3160
        i32.store offset=8
        local.get 0
        i32.load offset=8
        i32.const 216
        i32.add
        call $sgx_thread_mutex_lock
        drop
        block  ;; label = @3
          loop  ;; label = @4
            local.get 0
            i32.load offset=8
            i32.load offset=200
            i32.const 50
            i32.ge_s
            i32.const 1
            i32.and
            i32.eqz
            br_if 1 (;@3;)
            local.get 0
            i32.load offset=8
            i32.const 280
            i32.add
            local.get 0
            i32.load offset=8
            i32.const 216
            i32.add
            call $sgx_thread_cond_wait
            drop
            br 0 (;@4;)
          end
        end
        local.get 0
        i32.load offset=8
        local.get 0
        i32.load offset=8
        i32.load offset=204
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        local.get 0
        i32.load offset=8
        i32.load offset=204
        i32.store
        local.get 0
        i32.load offset=8
        local.tee 1
        local.get 1
        i32.load offset=204
        i32.const 1
        i32.add
        i32.store offset=204
        local.get 0
        i32.load offset=8
        local.tee 1
        local.get 1
        i32.load offset=204
        i32.const 50
        i32.rem_s
        i32.store offset=204
        local.get 0
        i32.load offset=8
        local.tee 1
        local.get 1
        i32.load offset=200
        i32.const 1
        i32.add
        i32.store offset=200
        local.get 0
        i32.load offset=8
        i32.const 256
        i32.add
        call $sgx_thread_cond_signal
        drop
        local.get 0
        i32.load offset=8
        i32.const 216
        i32.add
        call $sgx_thread_mutex_unlock
        drop
        local.get 0
        local.get 0
        i32.load offset=12
        i32.const 1
        i32.add
        i32.store offset=12
        br 0 (;@2;)
      end
    end
    local.get 0
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_ecall_consumer (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.const 0
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      call $ecall_consumer
      local.get 1
      local.get 1
      i32.load offset=4
      i32.store offset=12
    end
    local.get 1
    i32.load offset=12
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ecall_consumer (type 6)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i32.const 0
    i32.store offset=12
    block  ;; label = @1
      loop  ;; label = @2
        local.get 0
        i32.load offset=12
        i32.const 500
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 0
        i32.const 3160
        i32.store offset=8
        local.get 0
        i32.load offset=8
        i32.const 216
        i32.add
        call $sgx_thread_mutex_lock
        drop
        block  ;; label = @3
          loop  ;; label = @4
            local.get 0
            i32.load offset=8
            i32.load offset=200
            i32.const 0
            i32.le_s
            i32.const 1
            i32.and
            i32.eqz
            br_if 1 (;@3;)
            local.get 0
            i32.load offset=8
            i32.const 256
            i32.add
            local.get 0
            i32.load offset=8
            i32.const 216
            i32.add
            call $sgx_thread_cond_wait
            drop
            br 0 (;@4;)
          end
        end
        local.get 0
        i32.load offset=8
        local.set 1
        local.get 0
        i32.load offset=8
        local.tee 2
        local.get 2
        i32.load offset=208
        local.tee 2
        i32.const 1
        i32.add
        i32.store offset=208
        local.get 1
        local.get 2
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        i32.const 0
        i32.store
        local.get 0
        i32.load offset=8
        local.tee 1
        local.get 1
        i32.load offset=208
        i32.const 50
        i32.rem_s
        i32.store offset=208
        local.get 0
        i32.load offset=8
        local.tee 1
        local.get 1
        i32.load offset=200
        i32.const -1
        i32.add
        i32.store offset=200
        local.get 0
        i32.load offset=8
        i32.const 280
        i32.add
        call $sgx_thread_cond_signal
        drop
        local.get 0
        i32.load offset=8
        i32.const 216
        i32.add
        call $sgx_thread_mutex_unlock
        drop
        local.get 0
        local.get 0
        i32.load offset=12
        i32.const 1
        i32.add
        i32.store offset=12
        br 0 (;@2;)
      end
    end
    local.get 0
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $ocall_print_string (type 14) (param i32) (result i32)
    (local i32 i64 i64)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    local.get 1
    i32.const 0
    i32.store offset=36
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=40
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=40
        call $strlen
        i64.const 1
        i64.add
        local.set 2
        br 1 (;@1;)
      end
      i64.const 0
      local.set 2
    end
    local.get 1
    local.get 2
    i64.store offset=24
    local.get 1
    i32.const 0
    i32.store offset=16
    local.get 1
    i64.const 8
    i64.store offset=8
    local.get 1
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=40
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=40
        local.get 1
        i64.load offset=24
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=24
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 1
      local.get 1
      i64.load offset=8
      local.get 2
      i64.add
      local.tee 2
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=24
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      block  ;; label = @2
        local.get 2
        local.get 3
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i64.load offset=8
      call $sgx_ocalloc
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 1
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load
      i32.store offset=16
      local.get 1
      local.get 1
      i32.load
      i64.extend_i32_u
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store
      local.get 1
      local.get 1
      i64.load offset=8
      i64.const 8
      i64.sub
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=16
          local.get 1
          i32.load
          i32.store
          block  ;; label = @4
            local.get 1
            i64.load offset=24
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 2
            i32.store offset=44
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=40
            local.get 1
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 1
            i32.store offset=44
            br 3 (;@1;)
          end
          local.get 1
          local.get 1
          i32.load
          i64.extend_i32_u
          local.get 1
          i64.load offset=24
          i64.add
          i32.wrap_i64
          i32.store
          local.get 1
          local.get 1
          i64.load offset=8
          local.get 1
          i64.load offset=24
          i64.sub
          i64.store offset=8
          br 1 (;@2;)
        end
        local.get 1
        i32.load offset=16
        i32.const 0
        i32.store
      end
      local.get 1
      i32.const 0
      local.get 1
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=36
      block  ;; label = @2
        local.get 1
        i32.load offset=36
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 1
      local.get 1
      i32.load offset=36
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ocall_write_file (type 29) (param i32 i64 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=72
    local.get 3
    local.get 1
    i64.store offset=64
    local.get 3
    local.get 2
    i32.store offset=56
    local.get 3
    i32.const 0
    i32.store offset=52
    local.get 3
    local.get 3
    i64.load offset=64
    i64.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=56
        call $strlen
        i64.const 1
        i64.add
        local.set 1
        br 1 (;@1;)
      end
      i64.const 0
      local.set 1
    end
    local.get 3
    local.get 1
    i64.store offset=32
    local.get 3
    i32.const 0
    i32.store offset=24
    local.get 3
    i64.const 24
    i64.store offset=16
    local.get 3
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=72
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=72
        local.get 3
        i64.load offset=40
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 3
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=56
        local.get 3
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=40
          local.set 1
          br 1 (;@2;)
        end
        i64.const 0
        local.set 1
      end
      local.get 3
      local.get 3
      i64.load offset=16
      local.get 1
      i64.add
      local.tee 1
      i64.store offset=16
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=40
          local.set 4
          br 1 (;@2;)
        end
        i64.const 0
        local.set 4
      end
      block  ;; label = @2
        local.get 1
        local.get 4
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=32
          local.set 1
          br 1 (;@2;)
        end
        i64.const 0
        local.set 1
      end
      local.get 3
      local.get 3
      i64.load offset=16
      local.get 1
      i64.add
      local.tee 1
      i64.store offset=16
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=32
          local.set 4
          br 1 (;@2;)
        end
        i64.const 0
        local.set 4
      end
      block  ;; label = @2
        local.get 1
        local.get 4
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
      block  ;; label = @2
        local.get 3
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 3
        i32.const 1
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load offset=8
      i32.store offset=24
      local.get 3
      local.get 3
      i32.load offset=8
      i64.extend_i32_u
      i64.const 24
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 3
      local.get 3
      i64.load offset=16
      i64.const 24
      i64.sub
      i64.store offset=16
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=24
          local.get 3
          i32.load offset=8
          i32.store
          block  ;; label = @4
            local.get 3
            i64.load offset=40
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 2
            i32.store offset=76
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 3
            i32.load offset=8
            local.get 3
            i64.load offset=16
            local.get 3
            i32.load offset=72
            local.get 3
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 1
            i32.store offset=76
            br 3 (;@1;)
          end
          local.get 3
          local.get 3
          i32.load offset=8
          i64.extend_i32_u
          local.get 3
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 3
          local.get 3
          i64.load offset=16
          local.get 3
          i64.load offset=40
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=24
        i32.const 0
        i32.store
      end
      local.get 3
      i32.load offset=24
      local.get 3
      i64.load offset=64
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=24
          local.get 3
          i32.load offset=8
          i32.store offset=16
          block  ;; label = @4
            local.get 3
            i64.load offset=32
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 2
            i32.store offset=76
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 3
            i32.load offset=8
            local.get 3
            i64.load offset=16
            local.get 3
            i32.load offset=56
            local.get 3
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 1
            i32.store offset=76
            br 3 (;@1;)
          end
          local.get 3
          local.get 3
          i32.load offset=8
          i64.extend_i32_u
          local.get 3
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 3
          local.get 3
          i64.load offset=16
          local.get 3
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=24
        i32.const 0
        i32.store offset=16
      end
      local.get 3
      i32.const 1
      local.get 3
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=52
      block  ;; label = @2
        local.get 3
        i32.load offset=52
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 3
      local.get 3
      i32.load offset=52
      i32.store offset=76
    end
    local.get 3
    i32.load offset=76
    local.set 2
    local.get 3
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $ocall_pointer_user_check (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=24
    local.get 1
    i32.const 0
    i32.store offset=20
    local.get 1
    i32.const 0
    i32.store offset=16
    local.get 1
    i64.const 8
    i64.store offset=8
    local.get 1
    i32.const 0
    i32.store
    local.get 1
    local.get 1
    i64.load offset=8
    call $sgx_ocalloc
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 1
        i32.const 1
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load
      i32.store offset=16
      local.get 1
      local.get 1
      i32.load
      i64.extend_i32_u
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store
      local.get 1
      local.get 1
      i64.load offset=8
      i64.const 8
      i64.sub
      i64.store offset=8
      local.get 1
      i32.load offset=16
      local.get 1
      i32.load offset=24
      i32.store
      local.get 1
      i32.const 2
      local.get 1
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=20
      block  ;; label = @2
        local.get 1
        i32.load offset=20
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 1
      local.get 1
      i32.load offset=20
      i32.store offset=28
    end
    local.get 1
    i32.load offset=28
    local.set 0
    local.get 1
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ocall_pointer_in (type 14) (param i32) (result i32)
    (local i32 i64 i64)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=40
    local.get 1
    i32.const 0
    i32.store offset=36
    local.get 1
    i64.const 4
    i64.store offset=24
    local.get 1
    i32.const 0
    i32.store offset=16
    local.get 1
    i64.const 8
    i64.store offset=8
    local.get 1
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=40
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=40
        local.get 1
        i64.load offset=24
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=24
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 1
      local.get 1
      i64.load offset=8
      local.get 2
      i64.add
      local.tee 2
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=24
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      block  ;; label = @2
        local.get 2
        local.get 3
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i64.load offset=8
      call $sgx_ocalloc
      i32.store
      block  ;; label = @2
        local.get 1
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 1
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load
      i32.store offset=16
      local.get 1
      local.get 1
      i32.load
      i64.extend_i32_u
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store
      local.get 1
      local.get 1
      i64.load offset=8
      i64.const 8
      i64.sub
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=16
          local.get 1
          i32.load
          i32.store
          block  ;; label = @4
            local.get 1
            i64.load offset=24
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 2
            i32.store offset=44
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=40
            local.get 1
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 1
            i32.store offset=44
            br 3 (;@1;)
          end
          local.get 1
          local.get 1
          i32.load
          i64.extend_i32_u
          local.get 1
          i64.load offset=24
          i64.add
          i32.wrap_i64
          i32.store
          local.get 1
          local.get 1
          i64.load offset=8
          local.get 1
          i64.load offset=24
          i64.sub
          i64.store offset=8
          br 1 (;@2;)
        end
        local.get 1
        i32.load offset=16
        i32.const 0
        i32.store
      end
      local.get 1
      i32.const 3
      local.get 1
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=36
      block  ;; label = @2
        local.get 1
        i32.load offset=36
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 1
      local.get 1
      i32.load offset=36
      i32.store offset=44
    end
    local.get 1
    i32.load offset=44
    local.set 0
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ocall_pointer_out (type 14) (param i32) (result i32)
    (local i32 i64 i64)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=56
    local.get 1
    i32.const 0
    i32.store offset=52
    local.get 1
    i64.const 4
    i64.store offset=40
    local.get 1
    i32.const 0
    i32.store offset=32
    local.get 1
    i64.const 8
    i64.store offset=24
    local.get 1
    i32.const 0
    i32.store offset=16
    local.get 1
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=56
        local.get 1
        i64.load offset=40
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=40
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 1
      local.get 1
      i64.load offset=24
      local.get 2
      i64.add
      local.tee 2
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=40
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      block  ;; label = @2
        local.get 2
        local.get 3
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i64.load offset=24
      call $sgx_ocalloc
      i32.store offset=16
      block  ;; label = @2
        local.get 1
        i32.load offset=16
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 1
        i32.const 1
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=16
      i32.store offset=32
      local.get 1
      local.get 1
      i32.load offset=16
      i64.extend_i32_u
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store offset=16
      local.get 1
      local.get 1
      i64.load offset=24
      i64.const 8
      i64.sub
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=32
          local.get 1
          i32.load offset=16
          i32.store
          local.get 1
          local.get 1
          i32.load offset=16
          i32.store offset=8
          block  ;; label = @4
            local.get 1
            i64.load offset=40
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 2
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 1
          i32.load offset=8
          i32.const 0
          local.get 1
          i64.load offset=40
          i32.wrap_i64
          call $memset
          drop
          local.get 1
          local.get 1
          i32.load offset=16
          i64.extend_i32_u
          local.get 1
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 1
          local.get 1
          i64.load offset=24
          local.get 1
          i64.load offset=40
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 1
        i32.load offset=32
        i32.const 0
        i32.store
      end
      local.get 1
      i32.const 4
      local.get 1
      i32.load offset=32
      call $sgx_ocall
      i32.store offset=52
      block  ;; label = @2
        local.get 1
        i32.load offset=52
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=56
            local.get 1
            i64.load offset=40
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 1
      local.get 1
      i32.load offset=52
      i32.store offset=60
    end
    local.get 1
    i32.load offset=60
    local.set 0
    local.get 1
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ocall_pointer_in_out (type 14) (param i32) (result i32)
    (local i32 i64 i64)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=56
    local.get 1
    i32.const 0
    i32.store offset=52
    local.get 1
    i64.const 4
    i64.store offset=40
    local.get 1
    i32.const 0
    i32.store offset=32
    local.get 1
    i64.const 8
    i64.store offset=24
    local.get 1
    i32.const 0
    i32.store offset=16
    local.get 1
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=56
        local.get 1
        i64.load offset=40
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=40
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 1
      local.get 1
      i64.load offset=24
      local.get 2
      i64.add
      local.tee 2
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=40
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      block  ;; label = @2
        local.get 2
        local.get 3
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i64.load offset=24
      call $sgx_ocalloc
      i32.store offset=16
      block  ;; label = @2
        local.get 1
        i32.load offset=16
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 1
        i32.const 1
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=16
      i32.store offset=32
      local.get 1
      local.get 1
      i32.load offset=16
      i64.extend_i32_u
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store offset=16
      local.get 1
      local.get 1
      i64.load offset=24
      i64.const 8
      i64.sub
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=32
          local.get 1
          i32.load offset=16
          i32.store
          local.get 1
          local.get 1
          i32.load offset=16
          i32.store offset=8
          block  ;; label = @4
            local.get 1
            i64.load offset=40
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 2
            i32.store offset=60
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=16
            local.get 1
            i64.load offset=24
            local.get 1
            i32.load offset=56
            local.get 1
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 1
          local.get 1
          i32.load offset=16
          i64.extend_i32_u
          local.get 1
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 1
          local.get 1
          i64.load offset=24
          local.get 1
          i64.load offset=40
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 1
        i32.load offset=32
        i32.const 0
        i32.store
      end
      local.get 1
      i32.const 5
      local.get 1
      i32.load offset=32
      call $sgx_ocall
      i32.store offset=52
      block  ;; label = @2
        local.get 1
        i32.load offset=52
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 1
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 1
            i32.load offset=56
            local.get 1
            i64.load offset=40
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 1
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 1
      local.get 1
      i32.load offset=52
      i32.store offset=60
    end
    local.get 1
    i32.load offset=60
    local.set 0
    local.get 1
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $ocall_function_allow (type 27) (result i32)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i32.const 0
    i32.store offset=12
    local.get 0
    i32.const 6
    i32.const 0
    call $sgx_ocall
    i32.store offset=12
    local.get 0
    i32.load offset=12
    local.set 1
    local.get 0
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_oc_cpuidex (type 4) (param i32 i32 i32) (result i32)
    (local i32 i64 i64)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=56
    local.get 3
    local.get 1
    i32.store offset=52
    local.get 3
    local.get 2
    i32.store offset=48
    local.get 3
    i32.const 0
    i32.store offset=44
    local.get 3
    i64.const 16
    i64.store offset=32
    local.get 3
    i32.const 0
    i32.store offset=24
    local.get 3
    i64.const 16
    i64.store offset=16
    local.get 3
    i32.const 0
    i32.store offset=8
    local.get 3
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=56
        local.get 3
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=32
          local.set 4
          br 1 (;@2;)
        end
        i64.const 0
        local.set 4
      end
      local.get 3
      local.get 3
      i64.load offset=16
      local.get 4
      i64.add
      local.tee 4
      i64.store offset=16
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=32
          local.set 5
          br 1 (;@2;)
        end
        i64.const 0
        local.set 5
      end
      block  ;; label = @2
        local.get 4
        local.get 5
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
      block  ;; label = @2
        local.get 3
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 3
        i32.const 1
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load offset=8
      i32.store offset=24
      local.get 3
      local.get 3
      i32.load offset=8
      i64.extend_i32_u
      i64.const 16
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 3
      local.get 3
      i64.load offset=16
      i64.const 16
      i64.sub
      i64.store offset=16
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=24
          local.get 3
          i32.load offset=8
          i32.store
          local.get 3
          local.get 3
          i32.load offset=8
          i32.store
          block  ;; label = @4
            local.get 3
            i64.load offset=32
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 2
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 3
          i32.load
          i32.const 0
          local.get 3
          i64.load offset=32
          i32.wrap_i64
          call $memset
          drop
          local.get 3
          local.get 3
          i32.load offset=8
          i64.extend_i32_u
          local.get 3
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 3
          local.get 3
          i64.load offset=16
          local.get 3
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=24
        i32.const 0
        i32.store
      end
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=52
      i32.store offset=4
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=48
      i32.store offset=8
      local.get 3
      i32.const 7
      local.get 3
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=44
      block  ;; label = @2
        local.get 3
        i32.load offset=44
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 3
            i32.load offset=56
            local.get 3
            i64.load offset=32
            local.get 3
            i32.load
            local.get 3
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 3
      local.get 3
      i32.load offset=44
      i32.store offset=60
    end
    local.get 3
    i32.load offset=60
    local.set 2
    local.get 3
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $sgx_thread_wait_untrusted_event_ocall (type 7) (param i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=40
    local.get 2
    local.get 1
    i32.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=28
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 16
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    local.get 2
    local.get 2
    i64.load offset=16
    call $sgx_ocalloc
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 2
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.load offset=8
      i32.store offset=24
      local.get 2
      local.get 2
      i32.load offset=8
      i64.extend_i32_u
      i64.const 16
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 2
      local.get 2
      i64.load offset=16
      i64.const 16
      i64.sub
      i64.store offset=16
      local.get 2
      i32.load offset=24
      local.get 2
      i32.load offset=32
      i32.store offset=4
      local.get 2
      i32.const 8
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=28
      block  ;; label = @2
        local.get 2
        i32.load offset=28
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=40
          local.get 2
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=28
      i32.store offset=44
    end
    local.get 2
    i32.load offset=44
    local.set 1
    local.get 2
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_thread_set_untrusted_event_ocall (type 7) (param i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=40
    local.get 2
    local.get 1
    i32.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=28
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 16
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    local.get 2
    local.get 2
    i64.load offset=16
    call $sgx_ocalloc
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 2
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.load offset=8
      i32.store offset=24
      local.get 2
      local.get 2
      i32.load offset=8
      i64.extend_i32_u
      i64.const 16
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 2
      local.get 2
      i64.load offset=16
      i64.const 16
      i64.sub
      i64.store offset=16
      local.get 2
      i32.load offset=24
      local.get 2
      i32.load offset=32
      i32.store offset=4
      local.get 2
      i32.const 9
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=28
      block  ;; label = @2
        local.get 2
        i32.load offset=28
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=40
          local.get 2
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=28
      i32.store offset=44
    end
    local.get 2
    i32.load offset=44
    local.set 1
    local.get 2
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_thread_setwait_untrusted_events_ocall (type 4) (param i32 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=40
    local.get 3
    local.get 1
    i32.store offset=32
    local.get 3
    local.get 2
    i32.store offset=24
    local.get 3
    i32.const 0
    i32.store offset=20
    local.get 3
    i32.const 0
    i32.store offset=16
    local.get 3
    i64.const 24
    i64.store offset=8
    local.get 3
    i32.const 0
    i32.store
    local.get 3
    local.get 3
    i64.load offset=8
    call $sgx_ocalloc
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 3
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load
      i32.store offset=16
      local.get 3
      local.get 3
      i32.load
      i64.extend_i32_u
      i64.const 24
      i64.add
      i32.wrap_i64
      i32.store
      local.get 3
      local.get 3
      i64.load offset=8
      i64.const 24
      i64.sub
      i64.store offset=8
      local.get 3
      i32.load offset=16
      local.get 3
      i32.load offset=32
      i32.store offset=4
      local.get 3
      i32.load offset=16
      local.get 3
      i32.load offset=24
      i32.store offset=8
      local.get 3
      i32.const 10
      local.get 3
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=20
      block  ;; label = @2
        local.get 3
        i32.load offset=20
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 3
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=40
          local.get 3
          i32.load offset=16
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 3
      local.get 3
      i32.load offset=20
      i32.store offset=44
    end
    local.get 3
    i32.load offset=44
    local.set 2
    local.get 3
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $sgx_thread_set_multiple_untrusted_events_ocall (type 9) (param i32 i32 i64) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=56
    local.get 3
    local.get 1
    i32.store offset=48
    local.get 3
    local.get 2
    i64.store offset=40
    local.get 3
    i32.const 0
    i32.store offset=36
    local.get 3
    local.get 3
    i64.load offset=40
    i64.const 3
    i64.shl
    i64.store offset=24
    local.get 3
    i32.const 0
    i32.store offset=16
    local.get 3
    i64.const 24
    i64.store offset=8
    local.get 3
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=48
        local.get 3
        i64.load offset=24
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=24
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 3
      local.get 3
      i64.load offset=8
      local.get 2
      i64.add
      local.tee 2
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=24
          local.set 4
          br 1 (;@2;)
        end
        i64.const 0
        local.set 4
      end
      block  ;; label = @2
        local.get 2
        local.get 4
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i64.load offset=8
      call $sgx_ocalloc
      i32.store
      block  ;; label = @2
        local.get 3
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 3
        i32.const 1
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load
      i32.store offset=16
      local.get 3
      local.get 3
      i32.load
      i64.extend_i32_u
      i64.const 24
      i64.add
      i32.wrap_i64
      i32.store
      local.get 3
      local.get 3
      i64.load offset=8
      i64.const 24
      i64.sub
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=16
          local.get 3
          i32.load
          i32.store offset=4
          block  ;; label = @4
            local.get 3
            i64.load offset=24
            i64.const 7
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 2
            i32.store offset=60
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 3
            i32.load
            local.get 3
            i64.load offset=8
            local.get 3
            i32.load offset=48
            local.get 3
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 3
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 3
          local.get 3
          i32.load
          i64.extend_i32_u
          local.get 3
          i64.load offset=24
          i64.add
          i32.wrap_i64
          i32.store
          local.get 3
          local.get 3
          i64.load offset=8
          local.get 3
          i64.load offset=24
          i64.sub
          i64.store offset=8
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=16
        i32.const 0
        i32.store offset=4
      end
      local.get 3
      i32.load offset=16
      local.get 3
      i64.load offset=40
      i64.store offset=8
      local.get 3
      i32.const 11
      local.get 3
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=36
      block  ;; label = @2
        local.get 3
        i32.load offset=36
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 3
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=56
          local.get 3
          i32.load offset=16
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 3
      local.get 3
      i32.load offset=36
      i32.store offset=60
    end
    local.get 3
    i32.load offset=60
    local.set 1
    local.get 3
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $checksum_internal_char*__unsigned_long_ (type 0) (param i32 i64) (result i32)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 2
    local.get 0
    i32.store offset=24
    local.get 2
    local.get 1
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=12
    local.get 2
    local.get 2
    i32.load offset=24
    i32.store offset=8
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i64.load offset=16
        i64.const 1
        i64.gt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i32.load offset=12
        local.set 0
        local.get 2
        local.get 2
        i32.load offset=8
        local.tee 3
        i32.const 2
        i32.add
        i32.store offset=8
        local.get 2
        local.get 0
        local.get 3
        i32.load16_u
        i32.const 16
        i32.shl
        i32.const 16
        i32.shr_s
        i32.add
        i32.store offset=12
        local.get 2
        local.get 2
        i64.load offset=16
        i64.const 2
        i64.sub
        i64.store offset=16
        br 0 (;@2;)
      end
    end
    block  ;; label = @1
      local.get 2
      i64.load offset=16
      i64.const 0
      i64.gt_u
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      local.get 2
      i32.load offset=12
      local.get 2
      i32.load offset=8
      i32.load8_u
      i32.const 24
      i32.shl
      i32.const 24
      i32.shr_s
      i32.add
      i32.store offset=12
    end
    local.get 2
    i32.load offset=12
    i32.const -1
    i32.xor)
  (func $printf (type 7) (param i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 8240
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=8236
    local.get 2
    local.get 0
    i32.store offset=24
    local.get 2
    i32.const 32
    i32.add
    i32.const 0
    i32.const 8192
    call $memset
    drop
    local.get 2
    local.get 1
    i32.store
    local.get 2
    i32.const 32
    i32.add
    i64.const 8192
    local.get 2
    i32.load offset=24
    local.get 2
    call $vsnprintf
    drop
    local.get 2
    drop
    local.get 2
    i32.const 32
    i32.add
    call $ocall_print_string
    drop
    local.get 2
    i32.const 32
    i32.add
    i64.const 8191
    call $strnlen
    i32.wrap_i64
    i32.const 1
    i32.add
    local.set 0
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=8236
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 8240
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $almost_equal_double__double_ (type 30) (param f64 f64) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 2
    local.get 0
    f64.store offset=8
    local.get 2
    local.get 1
    f64.store
    local.get 2
    local.get 2
    f64.load offset=8
    local.get 2
    f64.load
    f64.sub
    f64.store offset=24
    local.get 2
    f64.load offset=24
    local.set 1
    local.get 2
    local.get 2
    f64.load offset=8
    local.get 2
    f64.load
    f64.add
    f64.store offset=16
    local.get 1
    f64.abs
    f64.const 0x1p-52 (;=2.22045e-16;)
    local.get 2
    f64.load offset=16
    f64.abs
    f64.mul
    f64.const 0x1p+1 (;=2;)
    f64.mul
    f64.le
    i32.const 1
    i32.and)
  (func $almost_equal_float__float_ (type 31) (param f32 f32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    local.get 0
    f32.store offset=4
    local.get 2
    local.get 1
    f32.store
    local.get 2
    local.get 2
    f32.load offset=4
    local.get 2
    f32.load
    f32.sub
    f32.store offset=12
    local.get 2
    f32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    f32.load offset=4
    local.get 2
    f32.load
    f32.add
    f32.store offset=8
    local.get 1
    f32.abs
    f32.const 0x1p-23 (;=1.19209e-07;)
    local.get 2
    f32.load offset=8
    f32.abs
    f32.mul
    f32.const 0x1p+1 (;=2;)
    f32.mul
    f32.le
    i32.const 1
    i32.and)
  (func $comparePublicKeys_unsigned_char*__unsigned_long__unsigned_char*__unsigned_long_ (type 2) (param i32 i64 i32 i64) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 4
    local.get 0
    i32.store offset=40
    local.get 4
    local.get 1
    i64.store offset=32
    local.get 4
    local.get 2
    i32.store offset=24
    local.get 4
    local.get 3
    i64.store offset=16
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=40
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=32
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=24
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=16
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 4
        i32.const 0
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 4
        i64.load offset=32
        local.get 4
        i64.load offset=16
        i64.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.const 0
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 4
      i64.const 0
      i64.store offset=8
      block  ;; label = @2
        local.get 4
        i64.load offset=8
        local.get 4
        i64.load offset=16
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 4
          i32.load offset=24
          local.get 4
          i64.load offset=8
          i32.wrap_i64
          i32.add
          i32.load8_u
          i32.const 255
          i32.and
          local.get 4
          i32.load offset=40
          local.get 4
          i64.load offset=8
          i32.wrap_i64
          i32.add
          i32.load8_u
          i32.const 255
          i32.and
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          br 1 (;@2;)
        end
        local.get 4
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 4
      i32.const 0
      i32.store offset=44
    end
    local.get 4
    i32.load offset=44)
  (func $isAuthorizedVoter_unsigned_char*__unsigned_long__unsigned_char*__unsigned_long_ (type 2) (param i32 i64 i32 i64) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=40
    local.get 4
    local.get 1
    i64.store offset=32
    local.get 4
    local.get 2
    i32.store offset=24
    local.get 4
    local.get 3
    i64.store offset=16
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=40
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=32
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=24
          i32.const 0
          i32.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=16
          i64.const 0
          i64.le_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 4
        i32.const 0
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 4
      local.get 4
      i64.load offset=16
      i32.wrap_i64
      i32.const 32
      i32.div_s
      i32.store offset=12
      local.get 4
      i32.const 0
      i32.store offset=8
      block  ;; label = @2
        loop  ;; label = @3
          local.get 4
          i32.load offset=8
          local.get 4
          i32.load offset=12
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          block  ;; label = @4
            local.get 4
            i32.load offset=40
            i64.const 32
            local.get 4
            i32.load offset=24
            local.get 4
            i32.load offset=8
            i32.const 5
            i32.shl
            i64.extend_i32_s
            i32.wrap_i64
            i32.add
            i64.const 32
            call $comparePublicKeys_unsigned_char*__unsigned_long__unsigned_char*__unsigned_long_
            i32.eqz
            br_if 0 (;@4;)
            local.get 4
            i32.const 1
            i32.store offset=44
            br 3 (;@1;)
          end
          local.get 4
          local.get 4
          i32.load offset=8
          i32.const 1
          i32.add
          i32.store offset=8
          br 0 (;@3;)
        end
      end
      local.get 4
      i32.const 0
      i32.store offset=44
    end
    local.get 4
    i32.load offset=44
    local.set 2
    local.get 4
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $std::__1::char_traits<char>::length_char_const*_ (type 5) (param i32) (result i64)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.load offset=8
    call $strlen
    local.set 2
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $__clang_call_terminate (type 3) (param i32)
    local.get 0
    call $__cxa_begin_catch
    drop
    call $std::terminate__
    unreachable)
  (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__tree_std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>_const&_ (type 19) (param i32 i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 192
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=24
    local.get 2
    local.get 1
    i32.store offset=16
    local.get 2
    local.get 2
    i32.load offset=24
    local.tee 1
    i32.const 4
    i32.add
    i32.store offset=32
    local.get 2
    local.get 2
    i32.load offset=32
    i32.store offset=96
    local.get 2
    local.get 2
    i32.load offset=96
    local.tee 0
    i32.store offset=104
    local.get 2
    local.get 0
    i32.store offset=112
    local.get 2
    i32.load offset=112
    i32.const 0
    i32.store
    local.get 2
    local.get 1
    i32.const 8
    i32.add
    i32.store offset=48
    local.get 2
    i64.const 0
    i64.store offset=40
    local.get 2
    i32.load offset=48
    local.set 0
    local.get 2
    local.get 2
    i32.const 40
    i32.add
    i32.store offset=120
    local.get 2
    i32.load offset=120
    i64.load
    local.set 3
    local.get 2
    local.get 2
    i32.const 56
    i32.add
    i32.store offset=128
    local.get 2
    local.get 0
    i32.store offset=144
    local.get 2
    local.get 3
    i64.store offset=136
    local.get 2
    i32.load offset=144
    local.set 0
    local.get 2
    local.get 2
    i32.const 152
    i32.add
    i32.store offset=168
    local.get 2
    local.get 2
    i32.const 136
    i32.add
    i32.store offset=160
    local.get 0
    local.get 2
    i32.load offset=160
    i64.load
    i64.store
    local.get 2
    local.get 1
    i32.store offset=64
    local.get 2
    local.get 2
    i32.load offset=64
    i32.const 4
    i32.add
    i32.store offset=176
    local.get 2
    local.get 2
    i32.load offset=176
    i32.store offset=184
    local.get 2
    local.get 2
    i32.load offset=184
    i32.store offset=72
    local.get 2
    local.get 2
    i32.load offset=72
    i32.store offset=80
    local.get 2
    i32.load offset=80
    local.set 0
    local.get 2
    local.get 1
    i32.store offset=88
    local.get 2
    i32.load offset=88
    local.get 0
    i32.store
    local.get 2
    i32.const 192
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::pair<char_const__int>_>_char_const&__std::__1::pair<char_const__int>&&_ (type 8) (param i32 i32 i32 i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 656
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 1
    i32.store offset=80
    local.get 4
    local.get 2
    i32.store offset=72
    local.get 4
    local.get 3
    i32.store offset=64
    local.get 4
    local.get 4
    i32.load offset=80
    local.tee 1
    local.get 4
    i32.const 56
    i32.add
    local.get 4
    i32.load offset=72
    call $std::__1::__tree_node_base<void*>*&_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__find_equal<char>_std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*&__char_const&_
    i32.store offset=48
    local.get 4
    local.get 4
    i32.load offset=48
    i32.load
    i32.store offset=40
    local.get 4
    i32.const 0
    i32.store8 offset=39
    block  ;; label = @1
      local.get 4
      i32.load offset=48
      i32.load
      i32.const 0
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      local.get 4
      i32.load offset=64
      i32.store offset=104
      local.get 4
      i32.const 16
      i32.add
      local.get 1
      local.get 4
      i32.load offset=104
      call $std::__1::unique_ptr<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>__std::__1::__tree_node_destructor<std::__1::allocator<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>_>_>_>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__construct_node<std::__1::pair<char_const__int>_>_std::__1::pair<char_const__int>&&_
      local.get 4
      i32.load offset=56
      local.set 2
      local.get 4
      i32.load offset=48
      local.set 3
      local.get 4
      local.get 4
      i32.const 16
      i32.add
      i32.store offset=112
      local.get 4
      local.get 4
      i32.load offset=112
      i32.store offset=192
      local.get 4
      local.get 4
      i32.load offset=192
      i32.store offset=200
      local.get 1
      local.get 2
      local.get 3
      local.get 4
      i32.load offset=200
      i32.load
      call $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__insert_node_at_std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*__std::__1::__tree_node_base<void*>*&__std::__1::__tree_node_base<void*>*_
      local.get 4
      local.get 4
      i32.const 16
      i32.add
      i32.store offset=128
      local.get 4
      local.get 4
      i32.load offset=128
      local.tee 1
      i32.store offset=216
      local.get 4
      local.get 4
      i32.load offset=216
      i32.store offset=224
      local.get 4
      local.get 4
      i32.load offset=224
      i32.load
      i32.store offset=120
      local.get 4
      local.get 1
      i32.store offset=208
      local.get 4
      local.get 4
      i32.load offset=208
      i32.store offset=232
      local.get 4
      i32.load offset=232
      i32.const 0
      i32.store
      local.get 4
      local.get 4
      i32.load offset=120
      i32.store offset=40
      local.get 4
      i32.const 1
      i32.store8 offset=39
      local.get 4
      local.get 4
      i32.const 16
      i32.add
      i32.store offset=136
      local.get 4
      local.get 4
      i32.load offset=136
      i32.store offset=328
      local.get 4
      i32.const 0
      i32.store offset=320
      local.get 4
      local.get 4
      i32.load offset=328
      local.tee 1
      i32.store offset=360
      local.get 4
      local.get 4
      i32.load offset=360
      i32.store offset=368
      local.get 4
      local.get 4
      i32.load offset=368
      i32.load
      i32.store offset=312
      local.get 4
      i32.load offset=320
      local.set 2
      local.get 4
      local.get 1
      i32.store offset=352
      local.get 4
      local.get 4
      i32.load offset=352
      i32.store offset=376
      local.get 4
      i32.load offset=376
      local.get 2
      i32.store
      block  ;; label = @2
        local.get 4
        i32.load offset=312
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        local.get 1
        i32.store offset=336
        local.get 4
        local.get 4
        i32.load offset=336
        i32.store offset=344
        local.get 4
        i32.load offset=312
        local.set 1
        local.get 4
        local.get 4
        i32.load offset=344
        i32.const 4
        i32.add
        i32.store offset=392
        local.get 4
        local.get 1
        i32.store offset=384
        block  ;; label = @3
          local.get 4
          i32.load offset=392
          local.tee 1
          i32.load8_u offset=4
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load
          local.set 2
          local.get 4
          local.get 4
          i32.load offset=384
          i32.const 16
          i32.add
          i32.store offset=424
          local.get 4
          local.get 4
          i32.load offset=424
          i32.store offset=472
          local.get 4
          i32.load offset=472
          local.set 3
          local.get 4
          local.get 2
          i32.store offset=416
          local.get 4
          local.get 3
          i32.store offset=408
          local.get 4
          i32.load offset=408
          local.set 2
          local.get 4
          local.get 4
          i32.load offset=416
          i32.store offset=464
          local.get 4
          local.get 2
          i32.store offset=456
        end
        block  ;; label = @3
          local.get 4
          i32.load offset=384
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=384
          local.set 2
          local.get 4
          local.get 1
          i32.load
          i32.store offset=448
          local.get 4
          local.get 2
          i32.store offset=440
          local.get 4
          i64.const 1
          i64.store offset=432
          local.get 4
          i32.load offset=440
          local.set 1
          local.get 4
          i64.load offset=432
          local.set 5
          local.get 4
          local.get 4
          i32.load offset=448
          i32.store offset=496
          local.get 4
          local.get 1
          i32.store offset=488
          local.get 4
          local.get 5
          i64.store offset=480
          local.get 4
          local.get 4
          i32.load offset=488
          i32.store offset=504
          local.get 4
          i32.load offset=504
          call $operator_delete_void*_
        end
      end
    end
    local.get 4
    i32.load offset=40
    local.set 1
    local.get 4
    local.get 4
    i32.store offset=160
    local.get 4
    local.get 1
    i32.store offset=152
    local.get 4
    i32.load offset=160
    local.get 4
    i32.load offset=152
    i32.store
    local.get 4
    local.get 4
    i32.const 88
    i32.add
    i32.store offset=184
    local.get 4
    local.get 4
    i32.store offset=176
    local.get 4
    local.get 4
    i32.const 39
    i32.add
    i32.store offset=168
    local.get 4
    i32.load offset=184
    local.set 1
    local.get 4
    local.get 4
    i32.load offset=176
    i32.store offset=640
    local.get 1
    local.get 4
    i32.load offset=640
    i64.load
    i64.store
    local.get 4
    local.get 4
    i32.load offset=168
    i32.store offset=648
    local.get 1
    local.get 4
    i32.load offset=648
    i32.load8_u
    i32.const 1
    i32.and
    i32.store8 offset=4
    local.get 4
    i32.load offset=88
    local.set 1
    local.get 0
    local.get 4
    i32.load8_u offset=92
    i32.store8 offset=4
    local.get 0
    local.get 1
    i32.store
    local.get 4
    i32.const 656
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::operator___char&&_ (type 7) (param i32 i32) (result i32)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 224
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=64
    local.get 2
    local.get 1
    i32.store offset=56
    local.get 2
    i32.load offset=64
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=56
    local.tee 0
    i32.store offset=96
    local.get 2
    local.get 2
    i32.load offset=96
    i32.store offset=72
    local.get 2
    local.get 2
    i32.load offset=72
    i32.store offset=88
    local.get 2
    i32.load offset=88
    local.set 3
    local.get 2
    local.get 2
    i32.const 80
    i32.add
    i32.store offset=128
    local.get 2
    local.get 3
    i32.store offset=120
    local.get 2
    i32.load offset=128
    local.set 3
    local.get 2
    local.get 2
    i32.load offset=120
    i32.store offset=136
    local.get 2
    i32.load offset=136
    local.set 4
    local.get 2
    local.get 3
    i32.store offset=152
    local.get 2
    local.get 4
    i32.store offset=144
    local.get 2
    i32.load offset=152
    local.set 3
    local.get 2
    local.get 2
    i32.load offset=144
    i32.store offset=160
    local.get 2
    i32.load offset=160
    local.set 4
    local.get 2
    local.get 3
    i32.store offset=176
    local.get 2
    local.get 4
    i32.store offset=168
    local.get 2
    i32.load offset=176
    local.set 3
    local.get 2
    local.get 2
    i32.load offset=168
    i32.store offset=184
    local.get 3
    local.get 2
    i32.load offset=184
    i32.store
    local.get 2
    local.get 2
    i32.load offset=80
    i32.store offset=32
    local.get 2
    local.get 2
    i32.const 104
    i32.add
    i32.store offset=192
    local.get 2
    i32.const 8
    i32.add
    local.get 1
    local.get 0
    i32.const 3117
    local.get 2
    i32.const 32
    i32.add
    local.get 2
    i32.const 24
    i32.add
    call $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>__std::__1::tuple<>_>_char_const&__std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>&&__std::__1::tuple<>&&_
    local.get 2
    i32.load8_u offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    i32.store offset=40
    local.get 2
    local.get 1
    i32.store8 offset=44
    local.get 2
    local.get 2
    i32.const 40
    i32.add
    i32.store offset=112
    local.get 2
    local.get 2
    i32.load offset=112
    i32.store offset=208
    local.get 2
    local.get 2
    i32.load offset=208
    i32.load
    i32.const 16
    i32.add
    i32.store offset=200
    local.get 2
    local.get 2
    i32.load offset=200
    i32.store offset=216
    local.get 2
    i32.load offset=216
    local.set 1
    local.get 2
    i32.const 224
    i32.add
    global.set $__stack_pointer
    local.get 1
    i32.const 4
    i32.add)
  (func $std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::find<char>_char_const&_ (type 7) (param i32 i32) (result i32)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 400
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=32
    local.get 2
    local.get 1
    i32.store offset=24
    local.get 2
    i32.load offset=24
    local.set 0
    local.get 2
    local.get 2
    i32.load offset=32
    local.tee 1
    i32.store offset=48
    local.get 2
    local.get 2
    i32.load offset=48
    i32.store offset=56
    local.get 2
    local.get 2
    i32.load offset=56
    i32.const 4
    i32.add
    i32.store offset=72
    local.get 2
    local.get 2
    i32.load offset=72
    i32.store offset=88
    local.get 2
    local.get 2
    i32.load offset=88
    i32.store offset=64
    local.get 2
    local.get 2
    i32.load offset=64
    i32.store offset=80
    local.get 2
    i32.load offset=80
    i32.load
    local.set 3
    local.get 2
    local.get 1
    i32.store offset=96
    local.get 2
    local.get 2
    i32.load offset=96
    i32.const 4
    i32.add
    i32.store offset=120
    local.get 2
    local.get 2
    i32.load offset=120
    i32.store offset=128
    local.get 2
    local.get 2
    i32.load offset=128
    i32.store offset=104
    local.get 2
    local.get 2
    i32.load offset=104
    i32.store offset=112
    local.get 2
    local.get 1
    local.get 0
    local.get 3
    local.get 2
    i32.load offset=112
    call $std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__lower_bound<char>_char_const&__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*_
    i32.store offset=16
    local.get 2
    local.get 1
    i32.store offset=280
    local.get 2
    local.get 2
    i32.load offset=280
    i32.store offset=296
    local.get 2
    local.get 2
    i32.load offset=296
    i32.const 4
    i32.add
    i32.store offset=320
    local.get 2
    local.get 2
    i32.load offset=320
    i32.store offset=328
    local.get 2
    local.get 2
    i32.load offset=328
    i32.store offset=304
    local.get 2
    local.get 2
    i32.load offset=304
    i32.store offset=312
    local.get 2
    i32.load offset=312
    local.set 0
    local.get 2
    local.get 2
    i32.const 288
    i32.add
    i32.store offset=360
    local.get 2
    local.get 0
    i32.store offset=352
    local.get 2
    i32.load offset=360
    local.get 2
    i32.load offset=352
    i32.store
    local.get 2
    local.get 2
    i32.load offset=288
    i32.store offset=8
    local.get 2
    local.get 2
    i32.const 16
    i32.add
    i32.store offset=216
    local.get 2
    local.get 2
    i32.const 8
    i32.add
    i32.store offset=208
    local.get 2
    i32.load offset=208
    local.set 0
    local.get 2
    local.get 2
    i32.load offset=216
    i32.store offset=392
    local.get 2
    local.get 0
    i32.store offset=384
    i32.const 0
    local.set 0
    block  ;; label = @1
      local.get 2
      i32.load offset=392
      i32.load
      local.get 2
      i32.load offset=384
      i32.load
      i32.eq
      i32.const -1
      i32.xor
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      local.get 1
      i32.store offset=136
      local.get 2
      local.get 2
      i32.load offset=136
      i32.const 8
      i32.add
      i32.store offset=168
      local.get 2
      local.get 2
      i32.load offset=168
      i32.store offset=176
      local.get 2
      i32.load offset=176
      local.set 0
      local.get 2
      i32.load offset=24
      local.set 3
      local.get 2
      local.get 2
      i32.const 16
      i32.add
      i32.store offset=336
      local.get 2
      local.get 2
      i32.load offset=336
      i32.store offset=344
      local.get 2
      i32.load offset=344
      i32.load
      local.set 4
      local.get 2
      local.get 0
      i32.store offset=160
      local.get 2
      local.get 3
      i32.store offset=152
      local.get 2
      local.get 4
      i32.const 16
      i32.add
      i32.store offset=144
      local.get 2
      i32.load offset=152
      local.set 0
      local.get 2
      i32.load offset=144
      local.set 3
      local.get 2
      local.get 2
      i32.load offset=160
      i32.store offset=200
      local.get 2
      local.get 0
      i32.store offset=192
      local.get 2
      local.get 3
      i32.store offset=184
      local.get 2
      i32.load offset=192
      i32.load8_u
      i32.const 24
      i32.shl
      i32.const 24
      i32.shr_s
      local.get 2
      i32.load offset=184
      i32.load8_u
      i32.const 24
      i32.shl
      i32.const 24
      i32.shr_s
      i32.lt_s
      i32.const -1
      i32.xor
      local.set 0
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.const 40
        i32.add
        local.get 2
        i32.const 16
        i32.add
        i64.load
        i64.store
        br 1 (;@1;)
      end
      local.get 2
      local.get 1
      i32.store offset=224
      local.get 2
      local.get 2
      i32.load offset=224
      i32.store offset=240
      local.get 2
      local.get 2
      i32.load offset=240
      i32.const 4
      i32.add
      i32.store offset=264
      local.get 2
      local.get 2
      i32.load offset=264
      i32.store offset=272
      local.get 2
      local.get 2
      i32.load offset=272
      i32.store offset=248
      local.get 2
      local.get 2
      i32.load offset=248
      i32.store offset=256
      local.get 2
      i32.load offset=256
      local.set 1
      local.get 2
      local.get 2
      i32.const 232
      i32.add
      i32.store offset=376
      local.get 2
      local.get 1
      i32.store offset=368
      local.get 2
      i32.load offset=376
      local.get 2
      i32.load offset=368
      i32.store
      local.get 2
      local.get 2
      i32.load offset=232
      i32.store offset=40
    end
    local.get 2
    i32.load offset=40
    local.set 1
    local.get 2
    i32.const 400
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::~map__ (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.load offset=8
    call $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::~__tree__
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::__tree_node_base<void*>*&_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__find_equal<char>_std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*&__char_const&_ (type 4) (param i32 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 304
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=40
    local.get 3
    local.get 1
    i32.store offset=32
    local.get 3
    local.get 2
    i32.store offset=24
    local.get 3
    local.get 3
    i32.load offset=40
    local.tee 2
    i32.store offset=56
    local.get 3
    local.get 3
    i32.load offset=56
    i32.store offset=64
    local.get 3
    local.get 3
    i32.load offset=64
    i32.const 4
    i32.add
    i32.store offset=80
    local.get 3
    local.get 3
    i32.load offset=80
    i32.store offset=96
    local.get 3
    local.get 3
    i32.load offset=96
    i32.store offset=72
    local.get 3
    local.get 3
    i32.load offset=72
    i32.store offset=88
    local.get 3
    local.get 3
    i32.load offset=88
    i32.load
    i32.store offset=16
    local.get 3
    local.get 2
    call $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__root_ptr___const
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=16
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        loop  ;; label = @3
          local.get 3
          local.get 2
          i32.store offset=152
          local.get 3
          local.get 3
          i32.load offset=152
          i32.const 8
          i32.add
          i32.store offset=224
          local.get 3
          local.get 3
          i32.load offset=224
          i32.store offset=248
          local.get 3
          i32.load offset=24
          local.set 1
          local.get 3
          i32.load offset=16
          local.set 0
          local.get 3
          local.get 3
          i32.load offset=248
          i32.store offset=176
          local.get 3
          local.get 1
          i32.store offset=168
          local.get 3
          local.get 0
          i32.const 16
          i32.add
          i32.store offset=160
          local.get 3
          i32.load offset=168
          local.set 1
          local.get 3
          i32.load offset=160
          local.set 0
          local.get 3
          local.get 3
          i32.load offset=176
          i32.store offset=296
          local.get 3
          local.get 1
          i32.store offset=288
          local.get 3
          local.get 0
          i32.store offset=280
          block  ;; label = @4
            block  ;; label = @5
              local.get 3
              i32.load offset=288
              i32.load8_u
              i32.const 24
              i32.shl
              i32.const 24
              i32.shr_s
              local.get 3
              i32.load offset=280
              i32.load8_u
              i32.const 24
              i32.shl
              i32.const 24
              i32.shr_s
              i32.lt_s
              i32.const 1
              i32.and
              i32.eqz
              br_if 0 (;@5;)
              block  ;; label = @6
                block  ;; label = @7
                  local.get 3
                  i32.load offset=16
                  i32.load
                  i32.const 0
                  i32.ne
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if 0 (;@7;)
                  local.get 3
                  local.get 3
                  i32.load offset=16
                  i32.store offset=192
                  local.get 3
                  local.get 3
                  i32.load offset=192
                  i32.store offset=8
                  local.get 3
                  local.get 3
                  i32.load offset=16
                  i32.load
                  i32.store offset=16
                  br 1 (;@6;)
                end
                local.get 3
                i32.load offset=32
                local.get 3
                i32.load offset=16
                i32.store
                local.get 3
                local.get 3
                i32.load offset=32
                i32.load
                i32.store offset=48
                br 5 (;@1;)
              end
              br 1 (;@4;)
            end
            local.get 3
            local.get 2
            i32.store offset=144
            local.get 3
            local.get 3
            i32.load offset=144
            i32.const 8
            i32.add
            i32.store offset=232
            local.get 3
            local.get 3
            i32.load offset=232
            i32.store offset=240
            local.get 3
            i32.load offset=16
            local.set 1
            local.get 3
            i32.load offset=24
            local.set 0
            local.get 3
            local.get 3
            i32.load offset=240
            i32.store offset=216
            local.get 3
            local.get 1
            i32.const 16
            i32.add
            i32.store offset=208
            local.get 3
            local.get 0
            i32.store offset=200
            local.get 3
            i32.load offset=208
            local.set 1
            local.get 3
            i32.load offset=200
            local.set 0
            local.get 3
            local.get 3
            i32.load offset=216
            i32.store offset=272
            local.get 3
            local.get 1
            i32.store offset=264
            local.get 3
            local.get 0
            i32.store offset=256
            block  ;; label = @5
              block  ;; label = @6
                local.get 3
                i32.load offset=264
                i32.load8_u
                i32.const 24
                i32.shl
                i32.const 24
                i32.shr_s
                local.get 3
                i32.load offset=256
                i32.load8_u
                i32.const 24
                i32.shl
                i32.const 24
                i32.shr_s
                i32.lt_s
                i32.const 1
                i32.and
                i32.eqz
                br_if 0 (;@6;)
                block  ;; label = @7
                  block  ;; label = @8
                    local.get 3
                    i32.load offset=16
                    i32.load offset=4
                    i32.const 0
                    i32.ne
                    i32.const 1
                    i32.and
                    i32.eqz
                    br_if 0 (;@8;)
                    local.get 3
                    local.get 3
                    i32.load offset=16
                    i32.const 4
                    i32.add
                    i32.store offset=184
                    local.get 3
                    local.get 3
                    i32.load offset=184
                    i32.store offset=8
                    local.get 3
                    local.get 3
                    i32.load offset=16
                    i32.load offset=4
                    i32.store offset=16
                    br 1 (;@7;)
                  end
                  local.get 3
                  i32.load offset=32
                  local.get 3
                  i32.load offset=16
                  i32.store
                  local.get 3
                  local.get 3
                  i32.load offset=16
                  i32.const 4
                  i32.add
                  i32.store offset=48
                  br 6 (;@1;)
                end
                br 1 (;@5;)
              end
              local.get 3
              i32.load offset=32
              local.get 3
              i32.load offset=16
              i32.store
              local.get 3
              local.get 3
              i32.load offset=8
              i32.store offset=48
              br 4 (;@1;)
            end
          end
          br 0 (;@3;)
        end
      end
      local.get 3
      local.get 2
      i32.store offset=104
      local.get 3
      local.get 3
      i32.load offset=104
      i32.const 4
      i32.add
      i32.store offset=128
      local.get 3
      local.get 3
      i32.load offset=128
      i32.store offset=136
      local.get 3
      local.get 3
      i32.load offset=136
      i32.store offset=112
      local.get 3
      local.get 3
      i32.load offset=112
      i32.store offset=120
      local.get 3
      i32.load offset=32
      local.get 3
      i32.load offset=120
      i32.store
      local.get 3
      local.get 3
      i32.load offset=32
      i32.load
      i32.store offset=48
    end
    local.get 3
    i32.load offset=48
    local.set 2
    local.get 3
    i32.const 304
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $std::__1::unique_ptr<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>__std::__1::__tree_node_destructor<std::__1::allocator<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>_>_>_>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__construct_node<std::__1::pair<char_const__int>_>_std::__1::pair<char_const__int>&&_ (type 20) (param i32 i32 i32)
    (local i32 i64 i32 i32)
    global.get $__stack_pointer
    i32.const 912
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=56
    local.get 3
    local.get 1
    i32.store offset=48
    local.get 3
    local.get 2
    i32.store offset=40
    local.get 3
    local.get 3
    i32.load offset=48
    i32.store offset=64
    local.get 3
    local.get 3
    i32.load offset=64
    i32.const 4
    i32.add
    i32.store offset=80
    local.get 3
    local.get 3
    i32.load offset=80
    i32.store offset=88
    local.get 3
    local.get 3
    i32.load offset=88
    i32.store offset=32
    local.get 3
    i32.const 0
    i32.const 1
    i32.and
    i32.store8 offset=31
    local.get 3
    local.get 3
    i32.load offset=32
    i32.store offset=136
    local.get 3
    i64.const 1
    i64.store offset=128
    local.get 3
    i64.load offset=128
    local.set 4
    local.get 3
    local.get 3
    i32.load offset=136
    i32.store offset=272
    local.get 3
    local.get 4
    i64.store offset=264
    local.get 3
    i32.const 0
    i32.store offset=256
    local.get 3
    i64.load offset=264
    local.set 4
    local.get 3
    local.get 3
    i32.load offset=272
    i32.store offset=280
    block  ;; label = @1
      local.get 4
      i64.const 461168601842738790
      i64.gt_u
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i64.const 8
      call $__cxa_allocate_exception
      local.tee 3
      call $std::bad_alloc::bad_alloc__
      local.get 3
      i32.const 0
      i32.const 2
      call $__cxa_throw
      unreachable
    end
    local.get 3
    local.get 3
    i64.load offset=264
    i64.const 40
    i64.mul
    i64.store offset=288
    local.get 3
    i64.load offset=288
    call $operator_new_unsigned_long_
    local.set 2
    local.get 3
    i32.load offset=32
    local.set 1
    local.get 3
    local.get 3
    i32.const 16
    i32.add
    i32.store offset=152
    local.get 3
    local.get 1
    i32.store offset=144
    local.get 3
    i32.const 0
    i32.store8 offset=143
    local.get 3
    i32.load offset=152
    local.tee 1
    local.get 3
    i32.load offset=144
    i32.store
    local.get 1
    local.get 3
    i32.load8_u offset=143
    i32.const 1
    i32.and
    i32.store8 offset=4
    local.get 3
    local.get 0
    i32.store offset=192
    local.get 3
    local.get 2
    i32.store offset=184
    local.get 3
    local.get 3
    i32.const 16
    i32.add
    i32.store offset=176
    local.get 3
    i32.load offset=192
    local.set 2
    local.get 3
    i32.load offset=184
    local.set 1
    local.get 3
    local.get 3
    i32.load offset=176
    i32.store offset=296
    local.get 3
    i32.const 160
    i32.add
    local.tee 5
    local.get 3
    i32.load offset=296
    local.tee 6
    i64.load
    i64.store
    local.get 5
    i32.const 8
    i32.add
    local.get 6
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 3
    i32.load8_u offset=164
    local.set 5
    local.get 3
    local.get 3
    i32.load offset=160
    i32.store offset=336
    local.get 3
    local.get 5
    i32.store8 offset=340
    local.get 3
    local.get 2
    i32.store offset=328
    local.get 3
    local.get 1
    i32.store offset=320
    local.get 3
    i32.load offset=328
    local.set 2
    local.get 3
    local.get 3
    i32.const 320
    i32.add
    i32.store offset=352
    local.get 3
    i32.load offset=352
    i32.load
    local.set 1
    local.get 3
    local.get 3
    i32.const 336
    i32.add
    i32.store offset=360
    local.get 3
    i32.const 304
    i32.add
    local.tee 5
    local.get 3
    i32.load offset=360
    local.tee 6
    i64.load
    i64.store
    local.get 5
    i32.const 8
    i32.add
    local.get 6
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 3
    i32.load8_u offset=308
    local.set 5
    local.get 3
    local.get 3
    i32.load offset=304
    i32.store offset=384
    local.get 3
    local.get 5
    i32.store8 offset=388
    local.get 3
    local.get 2
    i32.store offset=376
    local.get 3
    local.get 1
    i32.store offset=368
    local.get 3
    i32.load offset=376
    local.set 2
    local.get 3
    local.get 3
    i32.const 368
    i32.add
    i32.store offset=400
    local.get 2
    local.get 3
    i32.load offset=400
    i32.load
    i32.store
    local.get 3
    local.get 3
    i32.const 384
    i32.add
    i32.store offset=408
    local.get 2
    i32.const 4
    i32.add
    local.tee 2
    local.get 3
    i32.load offset=408
    local.tee 1
    i64.load
    i64.store
    local.get 2
    i32.const 8
    i32.add
    local.get 1
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 3
    i32.load offset=32
    local.set 2
    local.get 3
    local.get 0
    i32.store offset=240
    local.get 3
    local.get 3
    i32.load offset=240
    i32.store offset=480
    local.get 3
    local.get 3
    i32.load offset=480
    i32.store offset=488
    local.get 3
    local.get 3
    i32.load offset=488
    i32.load
    i32.const 16
    i32.add
    i32.store offset=72
    local.get 3
    local.get 3
    i32.load offset=72
    i32.store offset=96
    local.get 3
    i32.load offset=96
    local.set 1
    local.get 3
    local.get 3
    i32.load offset=40
    i32.store offset=104
    local.get 3
    i32.load offset=104
    local.set 5
    local.get 3
    local.get 2
    i32.store offset=224
    local.get 3
    local.get 1
    i32.store offset=216
    local.get 3
    local.get 5
    i32.store offset=208
    local.get 3
    i32.load offset=224
    local.set 2
    local.get 3
    i32.load offset=216
    local.set 1
    local.get 3
    local.get 3
    i32.load offset=208
    i32.store offset=232
    local.get 3
    i32.load offset=232
    local.set 5
    local.get 3
    local.get 2
    i32.store offset=432
    local.get 3
    local.get 1
    i32.store offset=424
    local.get 3
    local.get 5
    i32.store offset=416
    local.get 3
    i32.load offset=432
    local.set 2
    local.get 3
    i32.load offset=424
    local.set 1
    local.get 3
    local.get 3
    i32.load offset=416
    i32.store offset=440
    local.get 3
    i32.load offset=440
    local.set 5
    local.get 3
    local.get 2
    i32.store offset=464
    local.get 3
    local.get 1
    i32.store offset=456
    local.get 3
    local.get 5
    i32.store offset=448
    local.get 3
    i32.load offset=456
    local.set 2
    local.get 3
    local.get 3
    i32.load offset=448
    i32.store offset=472
    local.get 2
    local.get 3
    i32.load offset=472
    i64.load align=4
    i64.store align=4
    local.get 3
    local.get 0
    i32.store offset=248
    local.get 3
    local.get 3
    i32.load offset=248
    i32.store offset=496
    local.get 3
    local.get 3
    i32.load offset=496
    i32.store offset=504
    local.get 3
    i32.load offset=504
    i32.const 1
    i32.store8 offset=8
    local.get 3
    i32.const 1
    i32.const 1
    i32.and
    i32.store8 offset=31
    block  ;; label = @1
      local.get 3
      i32.load8_u offset=31
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      local.get 3
      local.get 0
      i32.store offset=112
      local.get 3
      local.get 3
      i32.load offset=112
      i32.store offset=600
      local.get 3
      i32.const 0
      i32.store offset=592
      local.get 3
      local.get 3
      i32.load offset=600
      local.tee 0
      i32.store offset=632
      local.get 3
      local.get 3
      i32.load offset=632
      i32.store offset=640
      local.get 3
      local.get 3
      i32.load offset=640
      i32.load
      i32.store offset=584
      local.get 3
      i32.load offset=592
      local.set 2
      local.get 3
      local.get 0
      i32.store offset=624
      local.get 3
      local.get 3
      i32.load offset=624
      i32.store offset=648
      local.get 3
      i32.load offset=648
      local.get 2
      i32.store
      block  ;; label = @2
        local.get 3
        i32.load offset=584
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        local.get 0
        i32.store offset=608
        local.get 3
        local.get 3
        i32.load offset=608
        i32.store offset=616
        local.get 3
        i32.load offset=584
        local.set 0
        local.get 3
        local.get 3
        i32.load offset=616
        i32.const 4
        i32.add
        i32.store offset=664
        local.get 3
        local.get 0
        i32.store offset=656
        block  ;; label = @3
          local.get 3
          i32.load offset=664
          local.tee 0
          i32.load8_u offset=4
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i32.load
          local.set 2
          local.get 3
          local.get 3
          i32.load offset=656
          i32.const 16
          i32.add
          i32.store offset=696
          local.get 3
          local.get 3
          i32.load offset=696
          i32.store offset=744
          local.get 3
          i32.load offset=744
          local.set 1
          local.get 3
          local.get 2
          i32.store offset=688
          local.get 3
          local.get 1
          i32.store offset=680
          local.get 3
          i32.load offset=680
          local.set 2
          local.get 3
          local.get 3
          i32.load offset=688
          i32.store offset=736
          local.get 3
          local.get 2
          i32.store offset=728
        end
        block  ;; label = @3
          local.get 3
          i32.load offset=656
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=656
          local.set 2
          local.get 3
          local.get 0
          i32.load
          i32.store offset=720
          local.get 3
          local.get 2
          i32.store offset=712
          local.get 3
          i64.const 1
          i64.store offset=704
          local.get 3
          i32.load offset=712
          local.set 0
          local.get 3
          i64.load offset=704
          local.set 4
          local.get 3
          local.get 3
          i32.load offset=720
          i32.store offset=768
          local.get 3
          local.get 0
          i32.store offset=760
          local.get 3
          local.get 4
          i64.store offset=752
          local.get 3
          local.get 3
          i32.load offset=760
          i32.store offset=776
          local.get 3
          i32.load offset=776
          call $operator_delete_void*_
        end
      end
    end
    local.get 3
    i32.const 912
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__insert_node_at_std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*__std::__1::__tree_node_base<void*>*&__std::__1::__tree_node_base<void*>*_ (type 8) (param i32 i32 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 128
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=32
    local.get 4
    local.get 1
    i32.store offset=24
    local.get 4
    local.get 2
    i32.store offset=16
    local.get 4
    local.get 3
    i32.store offset=8
    local.get 4
    i32.load offset=32
    local.set 3
    local.get 4
    i32.load offset=8
    i32.const 0
    i32.store
    local.get 4
    i32.load offset=8
    i32.const 0
    i32.store offset=4
    local.get 4
    i32.load offset=8
    local.get 4
    i32.load offset=24
    i32.store offset=8
    local.get 4
    i32.load offset=16
    local.get 4
    i32.load offset=8
    i32.store
    local.get 4
    local.get 3
    i32.store offset=80
    block  ;; label = @1
      local.get 4
      i32.load offset=80
      i32.load
      i32.load
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      local.get 3
      i32.store offset=72
      local.get 4
      i32.load offset=72
      i32.load
      i32.load
      local.set 2
      local.get 4
      local.get 3
      i32.store offset=64
      local.get 4
      i32.load offset=64
      local.get 2
      i32.store
    end
    local.get 4
    local.get 3
    i32.store offset=40
    local.get 4
    local.get 4
    i32.load offset=40
    i32.const 4
    i32.add
    i32.store offset=88
    local.get 4
    local.get 4
    i32.load offset=88
    i32.store offset=96
    local.get 4
    local.get 4
    i32.load offset=96
    i32.store offset=48
    local.get 4
    local.get 4
    i32.load offset=48
    i32.store offset=56
    local.get 4
    i32.load offset=56
    i32.load
    local.get 4
    i32.load offset=16
    i32.load
    call $void_std::__1::__tree_balance_after_insert<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*__std::__1::__tree_node_base<void*>*_
    local.get 4
    local.get 3
    i32.store offset=104
    local.get 4
    local.get 4
    i32.load offset=104
    i32.const 8
    i32.add
    i32.store offset=112
    local.get 4
    local.get 4
    i32.load offset=112
    i32.store offset=120
    local.get 4
    i32.load offset=120
    local.tee 3
    local.get 3
    i64.load
    i64.const 1
    i64.add
    i64.store
    local.get 4
    i32.const 128
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>__std::__1::tuple<>_>_char_const&__std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>&&__std::__1::tuple<>&&_ (type 32) (param i32 i32 i32 i32 i32 i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 480
    i32.sub
    local.tee 6
    global.set $__stack_pointer
    local.get 6
    local.get 1
    i32.store offset=96
    local.get 6
    local.get 2
    i32.store offset=88
    local.get 6
    local.get 3
    i32.store offset=80
    local.get 6
    local.get 4
    i32.store offset=72
    local.get 6
    local.get 5
    i32.store offset=64
    local.get 6
    local.get 6
    i32.load offset=96
    local.tee 1
    local.get 6
    i32.const 56
    i32.add
    local.get 6
    i32.load offset=88
    call $std::__1::__tree_node_base<void*>*&_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__find_equal<char>_std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*&__char_const&_
    i32.store offset=48
    local.get 6
    local.get 6
    i32.load offset=48
    i32.load
    i32.store offset=40
    local.get 6
    i32.const 0
    i32.store8 offset=39
    block  ;; label = @1
      local.get 6
      i32.load offset=48
      i32.load
      i32.const 0
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 6
      local.get 6
      i32.load offset=80
      i32.store offset=456
      local.get 6
      i32.load offset=456
      local.set 2
      local.get 6
      local.get 6
      i32.load offset=72
      i32.store offset=464
      local.get 6
      i32.load offset=464
      local.set 3
      local.get 6
      local.get 6
      i32.load offset=64
      i32.store offset=472
      local.get 6
      i32.const 16
      i32.add
      local.get 1
      local.get 2
      local.get 3
      local.get 6
      i32.load offset=472
      call $std::__1::unique_ptr<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>__std::__1::__tree_node_destructor<std::__1::allocator<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>_>_>_>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__construct_node<std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>__std::__1::tuple<>_>_std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>&&__std::__1::tuple<>&&_
      local.get 6
      i32.load offset=56
      local.set 2
      local.get 6
      i32.load offset=48
      local.set 3
      local.get 6
      local.get 6
      i32.const 16
      i32.add
      i32.store offset=120
      local.get 6
      local.get 6
      i32.load offset=120
      i32.store offset=192
      local.get 6
      local.get 6
      i32.load offset=192
      i32.store offset=200
      local.get 1
      local.get 2
      local.get 3
      local.get 6
      i32.load offset=200
      i32.load
      call $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__insert_node_at_std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*__std::__1::__tree_node_base<void*>*&__std::__1::__tree_node_base<void*>*_
      local.get 6
      local.get 6
      i32.const 16
      i32.add
      i32.store offset=136
      local.get 6
      local.get 6
      i32.load offset=136
      local.tee 1
      i32.store offset=216
      local.get 6
      local.get 6
      i32.load offset=216
      i32.store offset=224
      local.get 6
      local.get 6
      i32.load offset=224
      i32.load
      i32.store offset=128
      local.get 6
      local.get 1
      i32.store offset=208
      local.get 6
      local.get 6
      i32.load offset=208
      i32.store offset=232
      local.get 6
      i32.load offset=232
      i32.const 0
      i32.store
      local.get 6
      local.get 6
      i32.load offset=128
      i32.store offset=40
      local.get 6
      i32.const 1
      i32.store8 offset=39
      local.get 6
      local.get 6
      i32.const 16
      i32.add
      i32.store offset=144
      local.get 6
      local.get 6
      i32.load offset=144
      i32.store offset=256
      local.get 6
      i32.const 0
      i32.store offset=248
      local.get 6
      local.get 6
      i32.load offset=256
      local.tee 1
      i32.store offset=288
      local.get 6
      local.get 6
      i32.load offset=288
      i32.store offset=296
      local.get 6
      local.get 6
      i32.load offset=296
      i32.load
      i32.store offset=240
      local.get 6
      i32.load offset=248
      local.set 2
      local.get 6
      local.get 1
      i32.store offset=280
      local.get 6
      local.get 6
      i32.load offset=280
      i32.store offset=304
      local.get 6
      i32.load offset=304
      local.get 2
      i32.store
      block  ;; label = @2
        local.get 6
        i32.load offset=240
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        local.get 1
        i32.store offset=264
        local.get 6
        local.get 6
        i32.load offset=264
        i32.store offset=272
        local.get 6
        i32.load offset=240
        local.set 1
        local.get 6
        local.get 6
        i32.load offset=272
        i32.const 4
        i32.add
        i32.store offset=320
        local.get 6
        local.get 1
        i32.store offset=312
        block  ;; label = @3
          local.get 6
          i32.load offset=320
          local.tee 1
          i32.load8_u offset=4
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load
          local.set 2
          local.get 6
          local.get 6
          i32.load offset=312
          i32.const 16
          i32.add
          i32.store offset=352
          local.get 6
          local.get 6
          i32.load offset=352
          i32.store offset=400
          local.get 6
          i32.load offset=400
          local.set 3
          local.get 6
          local.get 2
          i32.store offset=344
          local.get 6
          local.get 3
          i32.store offset=336
          local.get 6
          i32.load offset=336
          local.set 2
          local.get 6
          local.get 6
          i32.load offset=344
          i32.store offset=392
          local.get 6
          local.get 2
          i32.store offset=384
        end
        block  ;; label = @3
          local.get 6
          i32.load offset=312
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=312
          local.set 2
          local.get 6
          local.get 1
          i32.load
          i32.store offset=376
          local.get 6
          local.get 2
          i32.store offset=368
          local.get 6
          i64.const 1
          i64.store offset=360
          local.get 6
          i32.load offset=368
          local.set 1
          local.get 6
          i64.load offset=360
          local.set 7
          local.get 6
          local.get 6
          i32.load offset=376
          i32.store offset=424
          local.get 6
          local.get 1
          i32.store offset=416
          local.get 6
          local.get 7
          i64.store offset=408
          local.get 6
          local.get 6
          i32.load offset=416
          i32.store offset=432
          local.get 6
          i32.load offset=432
          call $operator_delete_void*_
        end
      end
    end
    local.get 6
    i32.load offset=40
    local.set 1
    local.get 6
    local.get 6
    i32.const 8
    i32.add
    i32.store offset=160
    local.get 6
    local.get 1
    i32.store offset=152
    local.get 6
    i32.load offset=160
    local.get 6
    i32.load offset=152
    i32.store
    local.get 6
    local.get 6
    i32.const 104
    i32.add
    i32.store offset=184
    local.get 6
    local.get 6
    i32.const 8
    i32.add
    i32.store offset=176
    local.get 6
    local.get 6
    i32.const 39
    i32.add
    i32.store offset=168
    local.get 6
    i32.load offset=184
    local.set 1
    local.get 6
    local.get 6
    i32.load offset=176
    i32.store offset=440
    local.get 1
    local.get 6
    i32.load offset=440
    i64.load
    i64.store
    local.get 6
    local.get 6
    i32.load offset=168
    i32.store offset=448
    local.get 1
    local.get 6
    i32.load offset=448
    i32.load8_u
    i32.const 1
    i32.and
    i32.store8 offset=4
    local.get 6
    i32.load offset=104
    local.set 1
    local.get 0
    local.get 6
    i32.load8_u offset=108
    i32.store8 offset=4
    local.get 0
    local.get 1
    i32.store
    local.get 6
    i32.const 480
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__lower_bound<char>_char_const&__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*_ (type 33) (param i32 i32 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 128
    i32.sub
    local.tee 4
    local.get 0
    i32.store offset=24
    local.get 4
    local.get 1
    i32.store offset=16
    local.get 4
    local.get 2
    i32.store offset=8
    local.get 4
    local.get 3
    i32.store
    local.get 4
    i32.load offset=24
    local.set 3
    block  ;; label = @1
      loop  ;; label = @2
        local.get 4
        i32.load offset=8
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        local.get 3
        i32.store offset=40
        local.get 4
        local.get 4
        i32.load offset=40
        i32.const 8
        i32.add
        i32.store offset=72
        local.get 4
        local.get 4
        i32.load offset=72
        i32.store offset=80
        local.get 4
        i32.load offset=8
        local.set 2
        local.get 4
        i32.load offset=16
        local.set 1
        local.get 4
        local.get 4
        i32.load offset=80
        i32.store offset=64
        local.get 4
        local.get 2
        i32.const 16
        i32.add
        i32.store offset=56
        local.get 4
        local.get 1
        i32.store offset=48
        local.get 4
        i32.load offset=56
        local.set 2
        local.get 4
        i32.load offset=48
        local.set 1
        local.get 4
        local.get 4
        i32.load offset=64
        i32.store offset=104
        local.get 4
        local.get 2
        i32.store offset=96
        local.get 4
        local.get 1
        i32.store offset=88
        block  ;; label = @3
          block  ;; label = @4
            local.get 4
            i32.load offset=96
            i32.load8_u
            i32.const 24
            i32.shl
            i32.const 24
            i32.shr_s
            local.get 4
            i32.load offset=88
            i32.load8_u
            i32.const 24
            i32.shl
            i32.const 24
            i32.shr_s
            i32.lt_s
            i32.const 1
            i32.and
            br_if 0 (;@4;)
            local.get 4
            local.get 4
            i32.load offset=8
            i32.store
            local.get 4
            local.get 4
            i32.load offset=8
            i32.load
            i32.store offset=8
            br 1 (;@3;)
          end
          local.get 4
          local.get 4
          i32.load offset=8
          i32.load offset=4
          i32.store offset=8
        end
        br 0 (;@2;)
      end
    end
    local.get 4
    i32.load
    local.set 3
    local.get 4
    local.get 4
    i32.const 32
    i32.add
    i32.store offset=120
    local.get 4
    local.get 3
    i32.store offset=112
    local.get 4
    i32.load offset=120
    local.get 4
    i32.load offset=112
    i32.store
    local.get 4
    i32.load offset=32)
  (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::~__tree__ (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=8
    local.get 1
    local.get 1
    i32.load offset=8
    local.tee 0
    i32.store offset=16
    local.get 1
    local.get 1
    i32.load offset=16
    i32.store offset=24
    local.get 1
    local.get 1
    i32.load offset=24
    i32.const 4
    i32.add
    i32.store offset=40
    local.get 1
    local.get 1
    i32.load offset=40
    i32.store offset=56
    local.get 1
    local.get 1
    i32.load offset=56
    i32.store offset=32
    local.get 1
    local.get 1
    i32.load offset=32
    i32.store offset=48
    local.get 0
    local.get 1
    i32.load offset=48
    i32.load
    call $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::destroy_std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*_
    local.get 1
    i32.const 64
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::destroy_std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*_ (type 19) (param i32 i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 160
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=16
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    i32.load offset=16
    local.set 1
    block  ;; label = @1
      local.get 2
      i32.load offset=8
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      local.get 2
      i32.load offset=8
      i32.load
      call $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::destroy_std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*_
      local.get 1
      local.get 2
      i32.load offset=8
      i32.load offset=4
      call $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::destroy_std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*_
      local.get 2
      local.get 1
      i32.store offset=24
      local.get 2
      local.get 2
      i32.load offset=24
      i32.const 4
      i32.add
      i32.store offset=88
      local.get 2
      local.get 2
      i32.load offset=88
      i32.store offset=96
      local.get 2
      local.get 2
      i32.load offset=96
      i32.store
      local.get 2
      i32.load
      local.set 1
      local.get 2
      local.get 2
      i32.load offset=8
      i32.const 16
      i32.add
      i32.store offset=56
      local.get 2
      local.get 2
      i32.load offset=56
      i32.store offset=120
      local.get 2
      i32.load offset=120
      local.set 0
      local.get 2
      local.get 1
      i32.store offset=48
      local.get 2
      local.get 0
      i32.store offset=40
      local.get 2
      i32.load offset=40
      local.set 1
      local.get 2
      local.get 2
      i32.load offset=48
      i32.store offset=112
      local.get 2
      local.get 1
      i32.store offset=104
      local.get 2
      i32.load offset=8
      local.set 1
      local.get 2
      local.get 2
      i32.load
      i32.store offset=80
      local.get 2
      local.get 1
      i32.store offset=72
      local.get 2
      i64.const 1
      i64.store offset=64
      local.get 2
      i32.load offset=72
      local.set 1
      local.get 2
      i64.load offset=64
      local.set 3
      local.get 2
      local.get 2
      i32.load offset=80
      i32.store offset=144
      local.get 2
      local.get 1
      i32.store offset=136
      local.get 2
      local.get 3
      i64.store offset=128
      local.get 2
      local.get 2
      i32.load offset=136
      i32.store offset=152
      local.get 2
      i32.load offset=152
      call $operator_delete_void*_
    end
    local.get 2
    i32.const 160
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::unique_ptr<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>__std::__1::__tree_node_destructor<std::__1::allocator<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>_>_>_>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__construct_node<std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>__std::__1::tuple<>_>_std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>&&__std::__1::tuple<>&&_ (type 34) (param i32 i32 i32 i32 i32)
    (local i32 i64 i32)
    global.get $__stack_pointer
    i32.const 1120
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    local.get 0
    i32.store offset=72
    local.get 5
    local.get 1
    i32.store offset=64
    local.get 5
    local.get 2
    i32.store offset=56
    local.get 5
    local.get 3
    i32.store offset=48
    local.get 5
    local.get 4
    i32.store offset=40
    local.get 5
    local.get 5
    i32.load offset=64
    i32.store offset=80
    local.get 5
    local.get 5
    i32.load offset=80
    i32.const 4
    i32.add
    i32.store offset=96
    local.get 5
    local.get 5
    i32.load offset=96
    i32.store offset=104
    local.get 5
    local.get 5
    i32.load offset=104
    i32.store offset=32
    local.get 5
    i32.const 0
    i32.const 1
    i32.and
    i32.store8 offset=31
    local.get 5
    local.get 5
    i32.load offset=32
    i32.store offset=144
    local.get 5
    i64.const 1
    i64.store offset=136
    local.get 5
    i64.load offset=136
    local.set 6
    local.get 5
    local.get 5
    i32.load offset=144
    i32.store offset=240
    local.get 5
    local.get 6
    i64.store offset=232
    local.get 5
    i32.const 0
    i32.store offset=224
    local.get 5
    i64.load offset=232
    local.set 6
    local.get 5
    local.get 5
    i32.load offset=240
    i32.store offset=248
    block  ;; label = @1
      local.get 6
      i64.const 461168601842738790
      i64.gt_u
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i64.const 8
      call $__cxa_allocate_exception
      local.tee 5
      call $std::bad_alloc::bad_alloc__
      local.get 5
      i32.const 0
      i32.const 2
      call $__cxa_throw
      unreachable
    end
    local.get 5
    local.get 5
    i64.load offset=232
    i64.const 40
    i64.mul
    i64.store offset=256
    local.get 5
    i64.load offset=256
    call $operator_new_unsigned_long_
    local.set 4
    local.get 5
    i32.load offset=32
    local.set 3
    local.get 5
    local.get 5
    i32.const 16
    i32.add
    i32.store offset=160
    local.get 5
    local.get 3
    i32.store offset=152
    local.get 5
    i32.const 0
    i32.store8 offset=151
    local.get 5
    i32.load offset=160
    local.tee 3
    local.get 5
    i32.load offset=152
    i32.store
    local.get 3
    local.get 5
    i32.load8_u offset=151
    i32.const 1
    i32.and
    i32.store8 offset=4
    local.get 5
    local.get 0
    i32.store offset=200
    local.get 5
    local.get 4
    i32.store offset=192
    local.get 5
    local.get 5
    i32.const 16
    i32.add
    i32.store offset=184
    local.get 5
    i32.load offset=200
    local.set 4
    local.get 5
    i32.load offset=192
    local.set 3
    local.get 5
    local.get 5
    i32.load offset=184
    i32.store offset=264
    local.get 5
    i32.const 168
    i32.add
    local.tee 2
    local.get 5
    i32.load offset=264
    local.tee 1
    i64.load
    i64.store
    local.get 2
    i32.const 8
    i32.add
    local.get 1
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 5
    i32.load8_u offset=172
    local.set 2
    local.get 5
    local.get 5
    i32.load offset=168
    i32.store offset=304
    local.get 5
    local.get 2
    i32.store8 offset=308
    local.get 5
    local.get 4
    i32.store offset=296
    local.get 5
    local.get 3
    i32.store offset=288
    local.get 5
    i32.load offset=296
    local.set 4
    local.get 5
    local.get 5
    i32.const 288
    i32.add
    i32.store offset=320
    local.get 5
    i32.load offset=320
    i32.load
    local.set 3
    local.get 5
    local.get 5
    i32.const 304
    i32.add
    i32.store offset=328
    local.get 5
    i32.const 272
    i32.add
    local.tee 2
    local.get 5
    i32.load offset=328
    local.tee 1
    i64.load
    i64.store
    local.get 2
    i32.const 8
    i32.add
    local.get 1
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 5
    i32.load8_u offset=276
    local.set 2
    local.get 5
    local.get 5
    i32.load offset=272
    i32.store offset=352
    local.get 5
    local.get 2
    i32.store8 offset=356
    local.get 5
    local.get 4
    i32.store offset=344
    local.get 5
    local.get 3
    i32.store offset=336
    local.get 5
    i32.load offset=344
    local.set 4
    local.get 5
    local.get 5
    i32.const 336
    i32.add
    i32.store offset=368
    local.get 4
    local.get 5
    i32.load offset=368
    i32.load
    i32.store
    local.get 5
    local.get 5
    i32.const 352
    i32.add
    i32.store offset=376
    local.get 4
    i32.const 4
    i32.add
    local.tee 4
    local.get 5
    i32.load offset=376
    local.tee 3
    i64.load
    i64.store
    local.get 4
    i32.const 8
    i32.add
    local.get 3
    i32.const 8
    i32.add
    i64.load
    i64.store
    local.get 5
    i32.load offset=32
    local.set 4
    local.get 5
    local.get 0
    i32.store offset=208
    local.get 5
    local.get 5
    i32.load offset=208
    i32.store offset=384
    local.get 5
    local.get 5
    i32.load offset=384
    i32.store offset=392
    local.get 5
    local.get 5
    i32.load offset=392
    i32.load
    i32.const 16
    i32.add
    i32.store offset=88
    local.get 5
    local.get 5
    i32.load offset=88
    i32.store offset=112
    local.get 5
    i32.load offset=112
    local.set 3
    local.get 5
    local.get 5
    i32.load offset=56
    i32.store offset=816
    local.get 5
    i32.load offset=816
    local.set 2
    local.get 5
    local.get 5
    i32.load offset=48
    i32.store offset=824
    local.get 5
    i32.load offset=824
    local.set 1
    local.get 5
    local.get 5
    i32.load offset=40
    i32.store offset=832
    local.get 5
    i32.load offset=832
    local.set 7
    local.get 5
    local.get 4
    i32.store offset=880
    local.get 5
    local.get 3
    i32.store offset=872
    local.get 5
    local.get 2
    i32.store offset=864
    local.get 5
    local.get 1
    i32.store offset=856
    local.get 5
    local.get 7
    i32.store offset=848
    local.get 5
    i32.load offset=880
    local.set 4
    local.get 5
    i32.load offset=872
    local.set 3
    local.get 5
    local.get 5
    i32.load offset=864
    i32.store offset=888
    local.get 5
    i32.load offset=888
    local.set 2
    local.get 5
    local.get 5
    i32.load offset=856
    i32.store offset=896
    local.get 5
    i32.load offset=896
    local.set 1
    local.get 5
    local.get 5
    i32.load offset=848
    i32.store offset=904
    local.get 5
    i32.load offset=904
    local.set 7
    local.get 5
    local.get 4
    i32.store offset=944
    local.get 5
    local.get 3
    i32.store offset=936
    local.get 5
    local.get 2
    i32.store offset=928
    local.get 5
    local.get 1
    i32.store offset=920
    local.get 5
    local.get 7
    i32.store offset=912
    local.get 5
    i32.load offset=944
    local.set 4
    local.get 5
    i32.load offset=936
    local.set 3
    local.get 5
    local.get 5
    i32.load offset=928
    i32.store offset=952
    local.get 5
    i32.load offset=952
    local.set 2
    local.get 5
    local.get 5
    i32.load offset=920
    i32.store offset=960
    local.get 5
    i32.load offset=960
    local.set 1
    local.get 5
    local.get 5
    i32.load offset=912
    i32.store offset=968
    local.get 5
    i32.load offset=968
    local.set 7
    local.get 5
    local.get 4
    i32.store offset=1016
    local.get 5
    local.get 3
    i32.store offset=1008
    local.get 5
    local.get 2
    i32.store offset=1000
    local.get 5
    local.get 1
    i32.store offset=992
    local.get 5
    local.get 7
    i32.store offset=984
    local.get 5
    i32.load offset=1008
    local.set 4
    local.get 5
    local.get 5
    i32.load offset=1000
    i32.store offset=1024
    local.get 5
    local.get 5
    i32.load offset=992
    i32.store offset=1032
    local.get 5
    i32.const 976
    i32.add
    local.get 5
    i32.load offset=1032
    i64.load
    i64.store
    local.get 5
    local.get 5
    i32.load offset=984
    i32.store offset=1040
    local.get 5
    local.get 5
    i32.load offset=976
    i32.store offset=1064
    local.get 5
    local.get 4
    i32.store offset=1048
    local.get 5
    local.get 5
    i32.load offset=1048
    i32.store offset=1088
    local.get 5
    local.get 5
    i32.const 1064
    i32.add
    i32.store offset=1080
    local.get 5
    local.get 5
    i32.const 1056
    i32.add
    i32.store offset=1072
    local.get 5
    i32.load offset=1088
    local.set 4
    local.get 5
    local.get 5
    i32.load offset=1080
    i32.store offset=1104
    local.get 5
    local.get 5
    i32.load offset=1104
    i32.store offset=1112
    local.get 5
    local.get 5
    i32.load offset=1112
    i32.load
    i32.store offset=1096
    local.get 4
    local.get 5
    i32.load offset=1096
    i32.load8_u
    i32.store8
    local.get 4
    i32.const 0
    i32.store offset=4
    local.get 5
    local.get 0
    i32.store offset=216
    local.get 5
    local.get 5
    i32.load offset=216
    i32.store offset=400
    local.get 5
    local.get 5
    i32.load offset=400
    i32.store offset=408
    local.get 5
    i32.load offset=408
    i32.const 1
    i32.store8 offset=8
    local.get 5
    i32.const 1
    i32.const 1
    i32.and
    i32.store8 offset=31
    block  ;; label = @1
      local.get 5
      i32.load8_u offset=31
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      local.get 5
      local.get 0
      i32.store offset=120
      local.get 5
      local.get 5
      i32.load offset=120
      i32.store offset=504
      local.get 5
      i32.const 0
      i32.store offset=496
      local.get 5
      local.get 5
      i32.load offset=504
      local.tee 0
      i32.store offset=536
      local.get 5
      local.get 5
      i32.load offset=536
      i32.store offset=544
      local.get 5
      local.get 5
      i32.load offset=544
      i32.load
      i32.store offset=488
      local.get 5
      i32.load offset=496
      local.set 4
      local.get 5
      local.get 0
      i32.store offset=528
      local.get 5
      local.get 5
      i32.load offset=528
      i32.store offset=552
      local.get 5
      i32.load offset=552
      local.get 4
      i32.store
      block  ;; label = @2
        local.get 5
        i32.load offset=488
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        local.get 0
        i32.store offset=512
        local.get 5
        local.get 5
        i32.load offset=512
        i32.store offset=520
        local.get 5
        i32.load offset=488
        local.set 0
        local.get 5
        local.get 5
        i32.load offset=520
        i32.const 4
        i32.add
        i32.store offset=568
        local.get 5
        local.get 0
        i32.store offset=560
        block  ;; label = @3
          local.get 5
          i32.load offset=568
          local.tee 0
          i32.load8_u offset=4
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i32.load
          local.set 4
          local.get 5
          local.get 5
          i32.load offset=560
          i32.const 16
          i32.add
          i32.store offset=600
          local.get 5
          local.get 5
          i32.load offset=600
          i32.store offset=648
          local.get 5
          i32.load offset=648
          local.set 3
          local.get 5
          local.get 4
          i32.store offset=592
          local.get 5
          local.get 3
          i32.store offset=584
          local.get 5
          i32.load offset=584
          local.set 4
          local.get 5
          local.get 5
          i32.load offset=592
          i32.store offset=640
          local.get 5
          local.get 4
          i32.store offset=632
        end
        block  ;; label = @3
          local.get 5
          i32.load offset=560
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=560
          local.set 4
          local.get 5
          local.get 0
          i32.load
          i32.store offset=624
          local.get 5
          local.get 4
          i32.store offset=616
          local.get 5
          i64.const 1
          i64.store offset=608
          local.get 5
          i32.load offset=616
          local.set 0
          local.get 5
          i64.load offset=608
          local.set 6
          local.get 5
          local.get 5
          i32.load offset=624
          i32.store offset=672
          local.get 5
          local.get 0
          i32.store offset=664
          local.get 5
          local.get 6
          i64.store offset=656
          local.get 5
          local.get 5
          i32.load offset=664
          i32.store offset=680
          local.get 5
          i32.load offset=680
          call $operator_delete_void*_
        end
      end
    end
    local.get 5
    i32.const 1120
    i32.add
    global.set $__stack_pointer)
  (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__root_ptr___const (type 14) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 1
    local.get 0
    i32.store offset=8
    local.get 1
    local.get 1
    i32.load offset=8
    i32.store offset=16
    local.get 1
    local.get 1
    i32.load offset=16
    i32.const 4
    i32.add
    i32.store offset=32
    local.get 1
    local.get 1
    i32.load offset=32
    i32.store offset=48
    local.get 1
    local.get 1
    i32.load offset=48
    i32.store offset=24
    local.get 1
    local.get 1
    i32.load offset=24
    i32.store offset=40
    local.get 1
    local.get 1
    i32.load offset=40
    i32.store offset=56
    local.get 1
    i32.load offset=56)
  (func $void_std::__1::__tree_balance_after_insert<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*__std::__1::__tree_node_base<void*>*_ (type 19) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 176
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=24
    local.get 2
    local.get 1
    i32.store offset=16
    local.get 2
    i32.load offset=16
    local.get 2
    i32.load offset=16
    local.get 2
    i32.load offset=24
    i32.eq
    i32.const 1
    i32.and
    i32.store8 offset=12
    block  ;; label = @1
      loop  ;; label = @2
        i32.const 0
        local.set 1
        block  ;; label = @3
          local.get 2
          i32.load offset=16
          local.get 2
          i32.load offset=24
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          local.get 2
          i32.load offset=16
          i32.store offset=144
          local.get 2
          i32.load offset=144
          i32.load offset=8
          local.set 1
          local.get 1
          i32.load8_u offset=12
          i32.const -1
          i32.xor
          local.set 1
        end
        block  ;; label = @3
          local.get 1
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          local.get 2
          i32.load offset=16
          i32.store offset=136
          local.get 2
          i32.load offset=136
          i32.load offset=8
          local.set 1
          local.get 2
          local.get 1
          i32.store offset=168
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.load offset=168
              local.get 2
              i32.load offset=168
              i32.load offset=8
              i32.load
              i32.eq
              i32.const 1
              i32.and
              i32.eqz
              br_if 0 (;@5;)
              local.get 2
              local.get 2
              i32.load offset=16
              i32.store offset=128
              local.get 2
              i32.load offset=128
              i32.load offset=8
              local.set 1
              local.get 2
              local.get 1
              i32.store offset=120
              local.get 2
              i32.load offset=120
              i32.load offset=8
              local.set 1
              local.get 2
              local.get 1
              i32.load offset=4
              i32.store offset=8
              block  ;; label = @6
                block  ;; label = @7
                  local.get 2
                  i32.load offset=8
                  i32.const 0
                  i32.ne
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if 0 (;@7;)
                  local.get 2
                  i32.load offset=8
                  i32.load8_u offset=12
                  i32.const 1
                  i32.and
                  br_if 0 (;@7;)
                  local.get 2
                  local.get 2
                  i32.load offset=16
                  i32.store offset=112
                  local.get 2
                  i32.load offset=112
                  i32.load offset=8
                  local.set 1
                  local.get 2
                  local.get 1
                  i32.store offset=16
                  local.get 2
                  i32.load offset=16
                  i32.const 1
                  i32.store8 offset=12
                  local.get 2
                  local.get 2
                  i32.load offset=16
                  i32.store offset=104
                  local.get 2
                  i32.load offset=104
                  i32.load offset=8
                  local.set 1
                  local.get 2
                  local.get 1
                  i32.store offset=16
                  local.get 2
                  i32.load offset=16
                  local.get 2
                  i32.load offset=16
                  local.get 2
                  i32.load offset=24
                  i32.eq
                  i32.const 1
                  i32.and
                  i32.store8 offset=12
                  local.get 2
                  i32.load offset=8
                  i32.const 1
                  i32.store8 offset=12
                  br 1 (;@6;)
                end
                local.get 2
                local.get 2
                i32.load offset=16
                i32.store offset=160
                block  ;; label = @7
                  local.get 2
                  i32.load offset=160
                  local.get 2
                  i32.load offset=160
                  i32.load offset=8
                  i32.load
                  i32.eq
                  i32.const 1
                  i32.and
                  br_if 0 (;@7;)
                  local.get 2
                  local.get 2
                  i32.load offset=16
                  i32.store offset=96
                  local.get 2
                  i32.load offset=96
                  i32.load offset=8
                  local.set 1
                  local.get 2
                  local.get 1
                  i32.store offset=16
                  local.get 2
                  i32.load offset=16
                  call $void_std::__1::__tree_left_rotate<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*_
                end
                local.get 2
                local.get 2
                i32.load offset=16
                i32.store offset=88
                local.get 2
                i32.load offset=88
                i32.load offset=8
                local.set 1
                local.get 2
                local.get 1
                i32.store offset=16
                local.get 2
                i32.load offset=16
                i32.const 1
                i32.store8 offset=12
                local.get 2
                local.get 2
                i32.load offset=16
                i32.store offset=80
                local.get 2
                i32.load offset=80
                i32.load offset=8
                local.set 1
                local.get 2
                local.get 1
                i32.store offset=16
                local.get 2
                i32.load offset=16
                i32.const 0
                i32.store8 offset=12
                local.get 2
                i32.load offset=16
                call $void_std::__1::__tree_right_rotate<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*_
                br 5 (;@1;)
              end
              br 1 (;@4;)
            end
            local.get 2
            local.get 2
            i32.load offset=16
            i32.store offset=72
            local.get 2
            i32.load offset=72
            i32.load offset=8
            local.set 1
            local.get 2
            local.get 1
            i32.load offset=8
            i32.load
            i32.store
            block  ;; label = @5
              block  ;; label = @6
                local.get 2
                i32.load
                i32.const 0
                i32.ne
                i32.const 1
                i32.and
                i32.eqz
                br_if 0 (;@6;)
                local.get 2
                i32.load
                i32.load8_u offset=12
                i32.const 1
                i32.and
                br_if 0 (;@6;)
                local.get 2
                local.get 2
                i32.load offset=16
                i32.store offset=64
                local.get 2
                i32.load offset=64
                i32.load offset=8
                local.set 1
                local.get 2
                local.get 1
                i32.store offset=16
                local.get 2
                i32.load offset=16
                i32.const 1
                i32.store8 offset=12
                local.get 2
                local.get 2
                i32.load offset=16
                i32.store offset=56
                local.get 2
                i32.load offset=56
                i32.load offset=8
                local.set 1
                local.get 2
                local.get 1
                i32.store offset=16
                local.get 2
                i32.load offset=16
                local.get 2
                i32.load offset=16
                local.get 2
                i32.load offset=24
                i32.eq
                i32.const 1
                i32.and
                i32.store8 offset=12
                local.get 2
                i32.load
                i32.const 1
                i32.store8 offset=12
                br 1 (;@5;)
              end
              local.get 2
              local.get 2
              i32.load offset=16
              i32.store offset=152
              block  ;; label = @6
                local.get 2
                i32.load offset=152
                local.get 2
                i32.load offset=152
                i32.load offset=8
                i32.load
                i32.eq
                i32.const 1
                i32.and
                i32.eqz
                br_if 0 (;@6;)
                local.get 2
                local.get 2
                i32.load offset=16
                i32.store offset=48
                local.get 2
                i32.load offset=48
                i32.load offset=8
                local.set 1
                local.get 2
                local.get 1
                i32.store offset=16
                local.get 2
                i32.load offset=16
                call $void_std::__1::__tree_right_rotate<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*_
              end
              local.get 2
              local.get 2
              i32.load offset=16
              i32.store offset=40
              local.get 2
              i32.load offset=40
              i32.load offset=8
              local.set 1
              local.get 2
              local.get 1
              i32.store offset=16
              local.get 2
              i32.load offset=16
              i32.const 1
              i32.store8 offset=12
              local.get 2
              local.get 2
              i32.load offset=16
              i32.store offset=32
              local.get 2
              i32.load offset=32
              i32.load offset=8
              local.set 1
              local.get 2
              local.get 1
              i32.store offset=16
              local.get 2
              i32.load offset=16
              i32.const 0
              i32.store8 offset=12
              local.get 2
              i32.load offset=16
              call $void_std::__1::__tree_left_rotate<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*_
              br 4 (;@1;)
            end
          end
          br 1 (;@2;)
        end
      end
    end
    local.get 2
    i32.const 176
    i32.add
    global.set $__stack_pointer)
  (func $void_std::__1::__tree_left_rotate<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*_ (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 1
    local.get 0
    i32.store offset=8
    local.get 1
    local.get 1
    i32.load offset=8
    i32.load offset=4
    i32.store
    local.get 1
    i32.load offset=8
    local.get 1
    i32.load
    i32.load
    i32.store offset=4
    block  ;; label = @1
      local.get 1
      i32.load offset=8
      i32.load offset=4
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      i32.load offset=8
      local.set 0
      local.get 1
      local.get 1
      i32.load offset=8
      i32.load offset=4
      i32.store offset=56
      local.get 1
      local.get 0
      i32.store offset=48
      local.get 1
      i32.load offset=56
      local.get 1
      i32.load offset=48
      i32.store offset=8
    end
    local.get 1
    i32.load
    local.get 1
    i32.load offset=8
    i32.load offset=8
    i32.store offset=8
    local.get 1
    local.get 1
    i32.load offset=8
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        local.get 1
        i32.load offset=24
        i32.load offset=8
        i32.load
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        i32.load offset=8
        local.get 1
        i32.load
        i32.store
        br 1 (;@1;)
      end
      local.get 1
      i32.load
      local.set 0
      local.get 1
      local.get 1
      i32.load offset=8
      i32.store offset=16
      local.get 1
      i32.load offset=16
      i32.load offset=8
      local.get 0
      i32.store offset=4
    end
    local.get 1
    i32.load
    local.get 1
    i32.load offset=8
    i32.store
    local.get 1
    i32.load
    local.set 0
    local.get 1
    local.get 1
    i32.load offset=8
    i32.store offset=40
    local.get 1
    local.get 0
    i32.store offset=32
    local.get 1
    i32.load offset=40
    local.get 1
    i32.load offset=32
    i32.store offset=8)
  (func $void_std::__1::__tree_right_rotate<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*_ (type 3) (param i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 1
    local.get 0
    i32.store offset=8
    local.get 1
    local.get 1
    i32.load offset=8
    i32.load
    i32.store
    local.get 1
    i32.load offset=8
    local.get 1
    i32.load
    i32.load offset=4
    i32.store
    block  ;; label = @1
      local.get 1
      i32.load offset=8
      i32.load
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      i32.load offset=8
      local.set 0
      local.get 1
      local.get 1
      i32.load offset=8
      i32.load
      i32.store offset=56
      local.get 1
      local.get 0
      i32.store offset=48
      local.get 1
      i32.load offset=56
      local.get 1
      i32.load offset=48
      i32.store offset=8
    end
    local.get 1
    i32.load
    local.get 1
    i32.load offset=8
    i32.load offset=8
    i32.store offset=8
    local.get 1
    local.get 1
    i32.load offset=8
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=24
        local.get 1
        i32.load offset=24
        i32.load offset=8
        i32.load
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        i32.load offset=8
        local.get 1
        i32.load
        i32.store
        br 1 (;@1;)
      end
      local.get 1
      i32.load
      local.set 0
      local.get 1
      local.get 1
      i32.load offset=8
      i32.store offset=16
      local.get 1
      i32.load offset=16
      i32.load offset=8
      local.get 0
      i32.store offset=4
    end
    local.get 1
    i32.load
    local.get 1
    i32.load offset=8
    i32.store offset=4
    local.get 1
    i32.load
    local.set 0
    local.get 1
    local.get 1
    i32.load offset=8
    i32.store offset=40
    local.get 1
    local.get 0
    i32.store offset=32
    local.get 1
    i32.load offset=40
    local.get 1
    i32.load offset=32
    i32.store offset=8)
  (table (;0;) 39 39 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 69008))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1320))
  (global (;3;) i32 (i32.const 1024))
  (global (;4;) i32 (i32.const 3472))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 69008))
  (global (;7;) i32 (i32.const 0))
  (global (;8;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "ecall_gen_credentials" (func $ecall_gen_credentials))
  (export "ecall_unseal_and_export_pub" (func $ecall_unseal_and_export_pub))
  (export "ecall_run_election" (func $ecall_run_election))
  (export "ecall_check_voter" (func $ecall_check_voter))
  (export "ecall_type_char" (func $ecall_type_char))
  (export "ecall_type_int" (func $ecall_type_int))
  (export "ecall_type_float" (func $ecall_type_float))
  (export "ecall_type_double" (func $ecall_type_double))
  (export "ecall_type_size_t" (func $ecall_type_size_t))
  (export "ecall_type_wchar_t" (func $ecall_type_wchar_t))
  (export "ecall_type_struct" (func $ecall_type_struct))
  (export "ecall_type_enum_union" (func $ecall_type_enum_union))
  (export "ecall_pointer_user_check" (func $ecall_pointer_user_check))
  (export "ecall_pointer_in" (func $ecall_pointer_in))
  (export "ecall_pointer_out" (func $ecall_pointer_out))
  (export "ecall_pointer_in_out" (func $ecall_pointer_in_out))
  (export "ecall_pointer_string" (func $ecall_pointer_string))
  (export "ecall_pointer_string_const" (func $ecall_pointer_string_const))
  (export "ecall_pointer_size" (func $ecall_pointer_size))
  (export "ecall_pointer_count" (func $ecall_pointer_count))
  (export "ecall_pointer_isptr_readonly" (func $ecall_pointer_isptr_readonly))
  (export "ocall_pointer_attr" (func $ocall_pointer_attr))
  (export "ecall_array_user_check" (func $ecall_array_user_check))
  (export "ecall_array_in" (func $ecall_array_in))
  (export "ecall_array_out" (func $ecall_array_out))
  (export "ecall_array_in_out" (func $ecall_array_in_out))
  (export "ecall_array_isary" (func $ecall_array_isary))
  (export "ecall_function_public" (func $ecall_function_public))
  (export "ecall_function_private" (func $ecall_function_private))
  (export "ecall_malloc_free" (func $ecall_malloc_free))
  (export "ecall_sgx_cpuid" (func $ecall_sgx_cpuid))
  (export "ecall_exception" (func $ecall_exception))
  (export "ecall_map" (func $ecall_map))
  (export "ecall_increase_counter" (func $ecall_increase_counter))
  (export "ecall_producer" (func $ecall_producer))
  (export "ecall_consumer" (func $ecall_consumer))
  (export "ocall_print_string" (func $ocall_print_string))
  (export "ocall_write_file" (func $ocall_write_file))
  (export "ocall_pointer_user_check" (func $ocall_pointer_user_check))
  (export "ocall_pointer_in" (func $ocall_pointer_in))
  (export "ocall_pointer_out" (func $ocall_pointer_out))
  (export "ocall_pointer_in_out" (func $ocall_pointer_in_out))
  (export "ocall_function_allow" (func $ocall_function_allow))
  (export "sgx_oc_cpuidex" (func $sgx_oc_cpuidex))
  (export "sgx_thread_wait_untrusted_event_ocall" (func $sgx_thread_wait_untrusted_event_ocall))
  (export "sgx_thread_set_untrusted_event_ocall" (func $sgx_thread_set_untrusted_event_ocall))
  (export "sgx_thread_setwait_untrusted_events_ocall" (func $sgx_thread_setwait_untrusted_events_ocall))
  (export "sgx_thread_set_multiple_untrusted_events_ocall" (func $sgx_thread_set_multiple_untrusted_events_ocall))
  (export "_Z17checksum_internalPcm" (func $checksum_internal_char*__unsigned_long_))
  (export "printf" (func $printf))
  (export "_Z12almost_equaldd" (func $almost_equal_double__double_))
  (export "_Z12almost_equalff" (func $almost_equal_float__float_))
  (export "_Z17comparePublicKeysPhmS_m" (func $comparePublicKeys_unsigned_char*__unsigned_long__unsigned_char*__unsigned_long_))
  (export "_Z17isAuthorizedVoterPhmS_m" (func $isAuthorizedVoter_unsigned_char*__unsigned_long__unsigned_char*__unsigned_long_))
  (export "_ZNSt3__111char_traitsIcE6lengthEPKc" (func $std::__1::char_traits<char>::length_char_const*_))
  (export "__clang_call_terminate" (func $__clang_call_terminate))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEEC2ERKS6_" (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__tree_std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>_const&_))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE25__emplace_unique_key_argsIcJNS_4pairIKciEEEEENSB_INS_15__tree_iteratorIS2_PNS_11__tree_nodeIS2_PvEElEEbEERKT_DpOT0_" (func $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::pair<char_const__int>_>_char_const&__std::__1::pair<char_const__int>&&_))
  (export "_ZNSt3__13mapIciNS_4lessIcEENS_9allocatorINS_4pairIKciEEEEEixEOc" (func $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::operator___char&&_))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE4findIcEENS_15__tree_iteratorIS2_PNS_11__tree_nodeIS2_PvEElEERKT_" (func $std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::find<char>_char_const&_))
  (export "_ZNSt3__13mapIciNS_4lessIcEENS_9allocatorINS_4pairIKciEEEEED2Ev" (func $std::__1::map<char__int__std::__1::less<char>__std::__1::allocator<std::__1::pair<char_const__int>_>_>::~map__))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE12__find_equalIcEERPNS_16__tree_node_baseIPvEERPNS_15__tree_end_nodeISE_EERKT_" (func $std::__1::__tree_node_base<void*>*&_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__find_equal<char>_std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*&__char_const&_))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE16__construct_nodeIJNS_4pairIKciEEEEENS_10unique_ptrINS_11__tree_nodeIS2_PvEENS_22__tree_node_destructorINS7_ISH_EEEEEEDpOT_" (func $std::__1::unique_ptr<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>__std::__1::__tree_node_destructor<std::__1::allocator<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>_>_>_>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__construct_node<std::__1::pair<char_const__int>_>_std::__1::pair<char_const__int>&&_))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE16__insert_node_atEPNS_15__tree_end_nodeIPNS_16__tree_node_baseIPvEEEERSE_SE_" (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__insert_node_at_std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*__std::__1::__tree_node_base<void*>*&__std::__1::__tree_node_base<void*>*_))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE25__emplace_unique_key_argsIcJRKNS_21piecewise_construct_tENS_5tupleIJOcEEENSE_IJEEEEEENS_4pairINS_15__tree_iteratorIS2_PNS_11__tree_nodeIS2_PvEElEEbEERKT_DpOT0_" (func $std::__1::pair<std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>__bool>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__emplace_unique_key_args<char__std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>__std::__1::tuple<>_>_char_const&__std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>&&__std::__1::tuple<>&&_))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE13__lower_boundIcEENS_15__tree_iteratorIS2_PNS_11__tree_nodeIS2_PvEElEERKT_SF_PNS_15__tree_end_nodeIPNS_16__tree_node_baseISD_EEEE" (func $std::__1::__tree_iterator<std::__1::__value_type<char__int>__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__long>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__lower_bound<char>_char_const&__std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*__std::__1::__tree_end_node<std::__1::__tree_node_base<void*>*>*_))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEED2Ev" (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::~__tree__))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE7destroyEPNS_11__tree_nodeIS2_PvEE" (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::destroy_std::__1::__tree_node<std::__1::__value_type<char__int>__void*>*_))
  (export "_ZNSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE16__construct_nodeIJRKNS_21piecewise_construct_tENS_5tupleIJOcEEENSE_IJEEEEEENS_10unique_ptrINS_11__tree_nodeIS2_PvEENS_22__tree_node_destructorINS7_ISL_EEEEEEDpOT_" (func $std::__1::unique_ptr<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>__std::__1::__tree_node_destructor<std::__1::allocator<std::__1::__tree_node<std::__1::__value_type<char__int>__void*>_>_>_>_std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__construct_node<std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>__std::__1::tuple<>_>_std::__1::piecewise_construct_t_const&__std::__1::tuple<char&&>&&__std::__1::tuple<>&&_))
  (export "_ZNKSt3__16__treeINS_12__value_typeIciEENS_19__map_value_compareIcS2_NS_4lessIcEELb1EEENS_9allocatorIS2_EEE10__root_ptrEv" (func $std::__1::__tree<std::__1::__value_type<char__int>__std::__1::__map_value_compare<char__std::__1::__value_type<char__int>__std::__1::less<char>__true>__std::__1::allocator<std::__1::__value_type<char__int>_>_>::__root_ptr___const))
  (export "_ZNSt3__127__tree_balance_after_insertIPNS_16__tree_node_baseIPvEEEEvT_S5_" (func $void_std::__1::__tree_balance_after_insert<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*__std::__1::__tree_node_base<void*>*_))
  (export "_ZNSt3__118__tree_left_rotateIPNS_16__tree_node_baseIPvEEEEvT_" (func $void_std::__1::__tree_left_rotate<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*_))
  (export "_ZNSt3__119__tree_right_rotateIPNS_16__tree_node_baseIPvEEEEvT_" (func $void_std::__1::__tree_right_rotate<std::__1::__tree_node_base<void*>*>_std::__1::__tree_node_base<void*>*_))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 3))
  (export "__data_end" (global 4))
  (export "__global_base" (global 5))
  (export "__heap_base" (global 6))
  (export "__memory_base" (global 7))
  (export "__table_base" (global 8))
  (elem (;0;) (i32.const 1) func $std::runtime_error::~runtime_error__ $std::bad_alloc::~bad_alloc__ $sgx_ecall_gen_credentials $sgx_ecall_unseal_and_export_pub $sgx_ecall_run_election $sgx_ecall_check_voter $sgx_ecall_type_char $sgx_ecall_type_int $sgx_ecall_type_float $sgx_ecall_type_double $sgx_ecall_type_size_t $sgx_ecall_type_wchar_t $sgx_ecall_type_struct $sgx_ecall_type_enum_union $sgx_ecall_pointer_user_check $sgx_ecall_pointer_in $sgx_ecall_pointer_out $sgx_ecall_pointer_in_out $sgx_ecall_pointer_string $sgx_ecall_pointer_string_const $sgx_ecall_pointer_size $sgx_ecall_pointer_count $sgx_ecall_pointer_isptr_readonly $sgx_ocall_pointer_attr $sgx_ecall_array_user_check $sgx_ecall_array_in $sgx_ecall_array_out $sgx_ecall_array_in_out $sgx_ecall_array_isary $sgx_ecall_function_public $sgx_ecall_function_private $sgx_ecall_malloc_free $sgx_ecall_sgx_cpuid $sgx_ecall_exception $sgx_ecall_map $sgx_ecall_increase_counter $sgx_ecall_producer $sgx_ecall_consumer)
  (data $.rodata (i32.const 1024) "$\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\05\00\00\00\00\00\00\00\06\00\00\00\00\00\00\00\07\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\09\00\00\00\00\00\00\00\0a\00\00\00\00\00\00\00\0b\00\00\00\00\00\00\00\0c\00\00\00\00\00\00\00\0d\00\00\00\00\00\00\00\0e\00\00\00\00\00\00\00\0f\00\00\00\00\00\00\00\10\00\00\00\00\00\00\00\11\00\00\00\00\00\00\00\12\00\00\00\00\00\00\00\13\00\00\00\00\00\00\00\14\00\00\00\00\00\00\00\15\00\00\00\00\00\00\00\16\00\00\00\00\00\00\00\17\00\00\00\00\00\00\00\18\00\00\00\00\00\00\00\19\00\00\00\00\00\00\00\1a\00\00\00\00\00\00\00\1b\00\00\00\00\00\00\00\1c\00\00\00\00\00\00\00\1d\00\00\00\00\00\00\00\1e\00\00\00\00\00\00\00\1f\00\00\00\01\00\00\00 \00\00\00\00\00\00\00!\00\00\00\00\00\00\00\22\00\00\00\00\00\00\00#\00\00\00\00\00\00\00$\00\00\00\00\00\00\00%\00\00\00\00\00\00\00&\00\00\00\00\00\00\00\0c\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00ecall_array_isary\00ecall_array_out\00ecall_pointer_out\00ecall_array_in_out\00ecall_pointer_in_out\00ballot\00ecall_type_int\00ecall_type_struct\00ecall_type_float\00ecall_type_wchar_t\00ecall_type_size_t\00ocall_pointer_attr\00__s != nullptr\00ecall_type_char\00Enclave/TrustedLibrary/Libcxx.cpp\00Enclave/Edger8rSyntax/Arrays.cpp\00Enclave/Edger8rSyntax/Pointers.cpp\00Enclave/Edger8rSyntax/Types.cpp\00Enclave/TrustedLibrary/Libc.cpp\00ecall_map\00foo\00ecall_type_enum_union\00ecall_array_in\00ecall_pointer_in\00ballot.seal\00ecall_array_user_check\00arr[i] == i\00basic_string\00/opt/intel/sgxsdk/include/libcxx/string\00ecall_type_double\00ecall_malloc_free\00Something went wrong - %d\00SGX_SUCCESS\00ptr != NULL\00val == (size_t)12345678\00val.struct_foo_1 == 5678\00val == (wchar_t)0x1234\00val == 1234\00val.struct_foo_0 == 1234\00m['d'] == 4\00m['c'] == 3\00val == 0x12\00m['b'] == 2\000987654321\00*val == 1\00m['a'] == 1\00val1 == ENUM_FOO_0\00*val == 0\00arr[i] == 0\00almost_equal(val, (double)1234.5678)\00almost_equal(val, (float)1234.0)\00m.find('e') == m.end()\00Checksum(0x%p, %zu) = 0x%x\0a\00%s\0a\00ERROR on the creation of the key pairs %d\0a\00ERROR while sealing the credentials %d\0a\00ERROR while unsealing sgx_sealed_data - %d\0a\00AUTHORIZED VOTERS:  %d\0a\00COLLECTED VOTES:    %d\0a\00VALID VOTES:        %d\0a\00Failed to unseal data\0a\00VOTE NOT CASTED\0a\00VOTE WAS TALLIED\0a\00Something went wrong.\0a\00\0a--VOTING RESULTS--\0a\00VOTE WAS NOTE COUNTED (unauthorized voter)\0a\00\00")
  (data $.data (i32.const 3120) "\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"))
