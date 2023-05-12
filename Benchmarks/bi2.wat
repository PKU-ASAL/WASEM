(module
  (type (;0;) (func (param i64) (result i32)))
  (type (;1;) (func (param i32)))
  (type (;2;) (func (param i32 i64) (result i32)))
  (type (;3;) (func (param i32 i32 i32) (result i32)))
  (type (;4;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;6;) (func (param i32) (result i64)))
  (type (;7;) (func (param i32 i32) (result i32)))
  (type (;8;) (func))
  (type (;9;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;10;) (func (result i32)))
  (type (;11;) (func (param i32 i32 i64) (result i32)))
  (type (;12;) (func (param i32 i64 i32) (result i32)))
  (type (;13;) (func (param i32 i32)))
  (type (;14;) (func (param i32 i32 i32 i64) (result i32)))
  (type (;15;) (func (param i32) (result i32)))
  (type (;16;) (func (param i32 i64)))
  (type (;17;) (func (param i32 i64 i64)))
  (import "env" "malloc" (func $malloc (type 0)))
  (import "env" "free" (func $free (type 1)))
  (import "env" "realloc" (func $realloc (type 2)))
  (import "env" "memcpy" (func $memcpy (type 3)))
  (import "env" "sgx_rijndael128GCM_encrypt" (func $sgx_rijndael128GCM_encrypt (type 4)))
  (import "env" "sgx_rijndael128GCM_decrypt" (func $sgx_rijndael128GCM_decrypt (type 4)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 2)))
  (import "env" "memcpy_s" (func $memcpy_s (type 5)))
  (import "env" "memset" (func $memset (type 3)))
  (import "env" "strlen" (func $strlen (type 6)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 2)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 0)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 7)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 8)))
  (import "env" "vsnprintf" (func $vsnprintf (type 9)))
  (import "env" "__stack_chk_fail" (func $__stack_chk_fail (type 8)))
  (func $__wasm_call_ctors (type 8))
  (func $sgx_CryptStore_allocStore (type 10) (result i32)
    (local i32 i32)
    i64.const 32
    call $malloc
    local.tee 0
    i32.const 0
    i32.store16
    i64.const 4
    call $malloc
    local.set 1
    local.get 0
    i32.const 0
    i32.store offset=8
    local.get 0
    local.get 1
    i32.store offset=4
    local.get 0
    i64.const 1
    call $malloc
    i32.store offset=12
    local.get 0)
  (func $sgx_CryptStore_freeStore (type 1) (param i32)
    local.get 0
    i32.load offset=4
    call $free
    local.get 0
    i32.load offset=12
    call $free
    local.get 0
    call $free)
  (func $sgx_CryptStore_allocCryptData (type 7) (param i32 i32) (result i32)
    (local i32)
    i64.const 16
    call $malloc
    local.tee 2
    local.get 1
    i32.store offset=4
    local.get 2
    local.get 0
    i32.store
    local.get 2)
  (func $sgx_CryptStore_freeCryptData (type 1) (param i32)
    local.get 0
    call $free)
  (func $sgx_CryptStore_add (type 11) (param i32 i32 i64) (result i32)
    (local i32 i32)
    local.get 0
    local.get 0
    i32.load offset=4
    local.get 0
    i64.load16_u
    i64.const 2
    i64.shl
    i64.const 4
    i64.add
    call $realloc
    local.tee 3
    i32.store offset=4
    local.get 0
    local.get 0
    i32.load16_u
    local.tee 4
    i32.const 1
    i32.add
    i32.store16
    local.get 3
    local.get 4
    i32.const 2
    i32.shl
    i32.add
    local.get 0
    i32.load offset=8
    local.tee 3
    i32.store
    local.get 0
    local.get 0
    i32.load offset=12
    local.get 3
    i64.extend_i32_u
    local.get 2
    i64.add
    call $realloc
    local.tee 3
    i32.store offset=12
    local.get 3
    local.get 0
    i32.load offset=8
    local.tee 4
    i32.add
    local.get 1
    local.get 2
    i32.wrap_i64
    local.tee 3
    call $memcpy
    drop
    local.get 0
    local.get 4
    local.get 3
    i32.add
    i32.store offset=8
    local.get 0
    i32.load16_u
    i32.const -1
    i32.add
    i32.const 65535
    i32.and)
  (func $sgx_CryptStore_get (type 12) (param i32 i64 i32) (result i32)
    (local i32 i64 i32)
    i32.const 0
    local.set 3
    block  ;; label = @1
      local.get 0
      i64.load16_u
      local.tee 4
      local.get 1
      i64.le_u
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i64.const -1
          i64.add
          local.get 1
          i64.ne
          br_if 0 (;@3;)
          local.get 0
          i32.load offset=8
          local.get 0
          i32.load offset=4
          local.get 1
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          local.tee 3
          i32.sub
          local.set 5
          br 1 (;@2;)
        end
        local.get 0
        i32.load offset=4
        local.get 1
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        local.tee 3
        i32.const 4
        i32.add
        i32.load
        local.get 3
        i32.load
        local.tee 3
        i32.sub
        local.set 5
      end
      local.get 2
      local.get 0
      i32.load offset=12
      local.get 3
      i32.add
      local.get 5
      call $memcpy
      drop
      i32.const 1
      local.set 3
    end
    local.get 3)
  (func $sgx_CryptStore_toBytes (type 7) (param i32 i32) (result i32)
    (local i32 i64 i64 i32 i64 i32)
    local.get 0
    i32.load16_u
    local.tee 2
    i64.extend_i32_u
    i64.const 65535
    i64.and
    i64.const 2
    i64.shl
    local.tee 3
    i64.const 6
    i64.add
    local.tee 4
    local.get 0
    i32.load offset=8
    local.tee 5
    i64.extend_i32_u
    i64.add
    local.tee 6
    call $malloc
    local.tee 7
    local.get 2
    i32.store16
    local.get 7
    i32.const 2
    i32.add
    local.get 0
    i32.load offset=4
    local.get 3
    i32.wrap_i64
    local.tee 2
    call $memcpy
    drop
    local.get 7
    local.get 2
    i32.add
    i32.const 2
    i32.add
    local.get 5
    i32.store align=2
    local.get 7
    local.get 4
    i32.wrap_i64
    i32.add
    local.get 0
    i32.load offset=12
    local.get 5
    call $memcpy
    drop
    local.get 1
    local.get 6
    i64.store
    local.get 7)
  (func $sgx_CryptStore_fromBytes (type 13) (param i32 i32)
    (local i32 i64 i32)
    local.get 0
    local.get 1
    i32.load16_u
    local.tee 2
    i32.store16
    local.get 0
    local.get 0
    i32.load offset=4
    local.get 2
    i64.extend_i32_u
    i64.const 65535
    i64.and
    i64.const 2
    i64.shl
    local.tee 3
    call $realloc
    local.tee 2
    i32.store offset=4
    local.get 2
    local.get 1
    i32.const 2
    i32.add
    local.tee 1
    local.get 3
    i32.wrap_i64
    local.tee 4
    call $memcpy
    drop
    local.get 0
    local.get 1
    local.get 4
    i32.add
    local.tee 1
    i32.load
    local.tee 2
    i32.store offset=8
    local.get 0
    local.get 0
    i32.load offset=12
    local.get 2
    i64.extend_i32_u
    call $realloc
    local.tee 2
    i32.store offset=12
    local.get 2
    local.get 1
    i32.const 4
    i32.add
    local.get 0
    i32.load offset=8
    call $memcpy
    drop)
  (func $sgx_CryptStore_encrypt (type 3) (param i32 i32 i32) (result i32)
    (local i32 i64 i64 i32 i64 i32)
    local.get 1
    i32.load16_u
    local.tee 3
    i64.extend_i32_u
    i64.const 65535
    i64.and
    i64.const 2
    i64.shl
    local.tee 4
    i64.const 6
    i64.add
    local.tee 5
    local.get 1
    i32.load offset=8
    local.tee 6
    i64.extend_i32_u
    i64.add
    local.tee 7
    call $malloc
    local.tee 8
    local.get 3
    i32.store16
    local.get 8
    i32.const 2
    i32.add
    local.get 1
    i32.load offset=4
    local.get 4
    i32.wrap_i64
    local.tee 3
    call $memcpy
    drop
    local.get 8
    local.get 3
    i32.add
    i32.const 2
    i32.add
    local.get 6
    i32.store align=2
    local.get 8
    local.get 5
    i32.wrap_i64
    i32.add
    local.get 1
    i32.load offset=12
    local.get 6
    call $memcpy
    drop
    local.get 7
    i64.const 16
    i64.add
    local.tee 4
    call $malloc
    local.set 1
    local.get 0
    i32.load
    local.get 8
    local.get 7
    i32.wrap_i64
    local.tee 6
    local.get 1
    local.get 0
    i32.load offset=4
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 1
    local.get 6
    i32.add
    call $sgx_rijndael128GCM_encrypt
    local.set 0
    local.get 8
    call $free
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      call $free
      i32.const 0
      return
    end
    local.get 2
    local.get 4
    i64.store
    local.get 1)
  (func $sgx_CryptStore_decrypt (type 14) (param i32 i32 i32 i64) (result i32)
    (local i32 i32 i32)
    local.get 3
    i64.const -16
    i64.add
    local.tee 3
    call $malloc
    local.set 4
    block  ;; label = @1
      local.get 0
      i32.load
      local.get 2
      local.get 3
      i32.wrap_i64
      local.tee 5
      local.get 4
      local.get 0
      i32.load offset=4
      i32.const 12
      i32.const 0
      i32.const 0
      local.get 2
      local.get 5
      i32.add
      call $sgx_rijndael128GCM_decrypt
      local.tee 0
      br_if 0 (;@1;)
      local.get 1
      local.get 4
      i32.load16_u
      local.tee 2
      i32.store16
      local.get 1
      local.get 1
      i32.load offset=4
      local.get 2
      i64.extend_i32_u
      i64.const 65535
      i64.and
      i64.const 2
      i64.shl
      local.tee 3
      call $realloc
      local.tee 2
      i32.store offset=4
      local.get 2
      local.get 4
      i32.const 2
      i32.add
      local.tee 5
      local.get 3
      i32.wrap_i64
      local.tee 6
      call $memcpy
      drop
      local.get 1
      local.get 5
      local.get 6
      i32.add
      local.tee 2
      i32.load
      local.tee 5
      i32.store offset=8
      local.get 1
      local.get 1
      i32.load offset=12
      local.get 5
      i64.extend_i32_u
      call $realloc
      local.tee 5
      i32.store offset=12
      local.get 5
      local.get 2
      i32.const 4
      i32.add
      local.get 1
      i32.load offset=8
      call $memcpy
      drop
    end
    local.get 4
    call $free
    local.get 0)
  (func $sgx_init_store (type 15) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $init_store
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $init_store (type 8)
    (local i32 i32)
    i64.const 32
    call $malloc
    local.tee 0
    i32.const 0
    i32.store16
    i64.const 4
    call $malloc
    local.set 1
    local.get 0
    i32.const 0
    i32.store offset=8
    local.get 0
    local.get 1
    i32.store offset=4
    i64.const 1
    call $malloc
    local.set 1
    i32.const 0
    local.get 0
    i32.store offset=1168
    local.get 0
    local.get 1
    i32.store offset=12)
  (func $sgx_free_store (type 15) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $free_store
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $free_store (type 8)
    (local i32)
    i32.const 0
    i32.load offset=1168
    local.tee 0
    i32.load offset=4
    call $free
    local.get 0
    i32.load offset=12
    call $free
    local.get 0
    call $free)
  (func $sgx_add_to_store (type 15) (param i32) (result i32)
    (local i32 i64 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 16
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=8
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          local.get 2
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          local.get 2
          i64.eqz
          br_if 0 (;@3;)
          local.get 2
          call $malloc
          local.tee 3
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        local.get 2
        call $add_to_store
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 3
        local.get 2
        local.get 0
        local.get 2
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 3
        local.get 2
        call $add_to_store
        i32.const 0
        local.set 1
      end
      local.get 3
      call $free
    end
    local.get 1)
  (func $add_to_store (type 16) (param i32 i64)
    (local i32 i32 i32)
    i32.const 0
    i32.load offset=1168
    local.set 2
    local.get 2
    local.get 2
    i32.load offset=4
    local.get 2
    i64.load16_u
    i64.const 2
    i64.shl
    i64.const 4
    i64.add
    call $realloc
    local.tee 3
    i32.store offset=4
    local.get 2
    local.get 2
    i32.load16_u
    local.tee 4
    i32.const 1
    i32.add
    i32.store16
    local.get 3
    local.get 4
    i32.const 2
    i32.shl
    i32.add
    local.get 2
    i32.load offset=8
    local.tee 3
    i32.store
    local.get 2
    local.get 2
    i32.load offset=12
    local.get 3
    i64.extend_i32_u
    local.get 1
    i64.add
    call $realloc
    local.tee 3
    i32.store offset=12
    local.get 3
    local.get 2
    i32.load offset=8
    local.tee 4
    i32.add
    local.get 0
    local.get 1
    i32.wrap_i64
    local.tee 3
    call $memcpy
    drop
    local.get 2
    local.get 4
    local.get 3
    i32.add
    i32.store offset=8)
  (func $sgx_get_from_store (type 15) (param i32) (result i32)
    (local i32 i64 i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 24
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=8
      local.set 2
      i32.const 0
      local.set 3
      block  ;; label = @2
        local.get 0
        i32.load
        local.tee 4
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        local.get 2
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        i64.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          call $malloc
          local.tee 3
          br_if 0 (;@3;)
          i32.const 3
          return
        end
        local.get 3
        i32.const 0
        local.get 2
        i32.wrap_i64
        call $memset
        drop
      end
      local.get 3
      local.get 2
      local.get 0
      i64.load offset=16
      call $get_from_store
      i32.const 0
      local.set 1
      local.get 3
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      local.get 2
      local.get 3
      local.get 2
      call $memcpy_s
      local.set 0
      local.get 3
      call $free
      local.get 0
      i32.const 0
      i32.ne
      local.set 1
    end
    local.get 1)
  (func $get_from_store (type 17) (param i32 i64 i64)
    (local i32 i64 i32 i32)
    block  ;; label = @1
      i32.const 0
      i32.load offset=1168
      local.tee 3
      i64.load16_u
      local.tee 4
      local.get 2
      i64.le_u
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i64.const -1
          i64.add
          local.get 2
          i64.ne
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=8
          local.get 3
          i32.load offset=4
          local.get 2
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          local.tee 5
          i32.sub
          local.set 6
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=4
        local.get 2
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        local.tee 5
        i32.const 4
        i32.add
        i32.load
        local.get 5
        i32.load
        local.tee 5
        i32.sub
        local.set 6
      end
      local.get 0
      local.get 3
      i32.load offset=12
      local.get 5
      i32.add
      local.get 6
      call $memcpy
      drop
    end)
  (func $sgx_encrypt_store (type 15) (param i32) (result i32)
    (local i32 i32 i64)
    i32.const 2
    local.set 1
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i64.const 16
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i32.load
        local.tee 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
        local.get 0
        i64.load offset=8
        local.tee 3
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i64.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          local.get 3
          call $malloc
          local.tee 0
          br_if 0 (;@3;)
          i32.const 3
          return
        end
        i32.const 1
        local.set 1
        block  ;; label = @3
          local.get 0
          local.get 3
          local.get 2
          local.get 3
          call $memcpy_s
          br_if 0 (;@3;)
          local.get 3
          i32.wrap_i64
          local.get 0
          i32.add
          i32.const -1
          i32.add
          i32.const 0
          i32.store8
          local.get 3
          local.get 0
          call $strlen
          i64.const 1
          i64.add
          i64.ne
          br_if 0 (;@3;)
          local.get 0
          call $encrypt_store
          i32.const 0
          local.set 1
        end
        local.get 0
        call $free
      end
      local.get 1
      return
    end
    i32.const 0
    call $encrypt_store
    i32.const 0)
  (func $encrypt_store (type 1) (param i32)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    i32.const 0
    i32.load
    i32.store offset=44
    local.get 1
    i32.const 0
    i64.load offset=1144
    i64.store offset=24
    local.get 1
    i32.const 0
    i64.load offset=1136
    i64.store offset=16
    local.get 1
    i32.const 40
    i32.add
    i32.const 0
    i32.load offset=1160 align=1
    i32.store
    local.get 1
    i32.const 0
    i64.load offset=1152 align=1
    i64.store offset=32
    i64.const 16
    call $malloc
    local.tee 2
    local.get 1
    i32.const 32
    i32.add
    i32.store offset=4
    local.get 2
    local.get 1
    i32.const 16
    i32.add
    i32.store
    local.get 2
    i32.const 0
    i32.load offset=1168
    local.get 1
    i32.const 8
    i32.add
    call $sgx_CryptStore_encrypt_sgx_CryptStore_CryptData*__sgx_CryptStore_Store*__unsigned_long*_
    local.set 3
    local.get 2
    call $free
    local.get 0
    local.get 3
    local.get 1
    i64.load offset=8
    call $ocall_write_resource
    drop
    local.get 3
    call $free
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 1
      i32.load offset=44
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 1
    i32.const 48
    i32.add
    global.set $__stack_pointer)
  (func $sgx_decrypt_store (type 15) (param i32) (result i32)
    (local i32 i64 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 16
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=8
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          local.get 2
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          local.get 2
          i64.eqz
          br_if 0 (;@3;)
          local.get 2
          call $malloc
          local.tee 3
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        local.get 2
        call $decrypt_store
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 3
        local.get 2
        local.get 0
        local.get 2
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 3
        local.get 2
        call $decrypt_store
        i32.const 0
        local.set 1
      end
      local.get 3
      call $free
    end
    local.get 1)
  (func $decrypt_store (type 16) (param i32 i64)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=28
    local.get 2
    i32.const 0
    i64.load offset=1144
    i64.store offset=8
    local.get 2
    i32.const 0
    i64.load offset=1136
    i64.store
    local.get 2
    i32.const 24
    i32.add
    i32.const 0
    i32.load offset=1160 align=1
    i32.store
    local.get 2
    i32.const 0
    i64.load offset=1152 align=1
    i64.store offset=16
    i64.const 16
    call $malloc
    local.tee 3
    local.get 2
    i32.const 16
    i32.add
    i32.store offset=4
    local.get 3
    local.get 2
    i32.store
    local.get 3
    i32.const 0
    i32.load offset=1168
    local.get 0
    local.get 1
    call $sgx_CryptStore_decrypt_sgx_CryptStore_CryptData*__sgx_CryptStore_Store*__unsigned_char*__unsigned_long_
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=28
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $sgx_store_to_bytes (type 15) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $store_to_bytes
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $store_to_bytes (type 8)
    (local i32 i32 i64 i64 i32 i64 i32)
    i32.const 0
    i32.load offset=1168
    local.tee 0
    i32.load16_u
    local.tee 1
    i64.extend_i32_u
    i64.const 65535
    i64.and
    i64.const 2
    i64.shl
    local.tee 2
    i64.const 6
    i64.add
    local.tee 3
    local.get 0
    i32.load offset=8
    local.tee 4
    i64.extend_i32_u
    i64.add
    local.tee 5
    call $malloc
    local.tee 6
    local.get 1
    i32.store16
    local.get 6
    i32.const 2
    i32.add
    local.get 0
    i32.load offset=4
    local.get 2
    i32.wrap_i64
    local.tee 1
    call $memcpy
    drop
    local.get 6
    local.get 1
    i32.add
    i32.const 2
    i32.add
    local.get 4
    i32.store align=2
    local.get 6
    local.get 3
    i32.wrap_i64
    i32.add
    local.get 0
    i32.load offset=12
    local.get 4
    call $memcpy
    drop
    local.get 6
    local.get 5
    call $ocall_print_raw
    drop
    local.get 6
    call $free)
  (func $ocall_write_resource (type 11) (param i32 i32 i64) (result i32)
    (local i32 i64 i32 i64 i64 i64 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 0
              i32.eqz
              br_if 0 (;@5;)
              i32.const 2
              local.set 3
              local.get 0
              local.get 0
              call $strlen
              i64.const 1
              i64.add
              local.tee 4
              call $sgx_is_within_enclave
              i32.eqz
              br_if 4 (;@1;)
              local.get 1
              br_if 1 (;@4;)
              local.get 4
              i64.const -25
              i64.gt_u
              br_if 4 (;@1;)
              br 2 (;@3;)
            end
            i64.const 0
            local.set 4
            local.get 1
            i32.eqz
            br_if 1 (;@3;)
          end
          i32.const 2
          local.set 3
          local.get 1
          local.get 2
          call $sgx_is_within_enclave
          i32.eqz
          br_if 2 (;@1;)
          local.get 4
          i64.const -25
          i64.gt_u
          br_if 2 (;@1;)
          i32.const 0
          local.set 5
          local.get 2
          local.set 6
          local.get 4
          local.get 2
          i64.add
          local.tee 7
          i64.const 24
          i64.add
          local.tee 8
          local.get 2
          i64.lt_u
          br_if 2 (;@1;)
          br 1 (;@2;)
        end
        local.get 4
        i64.const 24
        i64.add
        local.set 8
        i32.const 1
        local.set 5
        i64.const 0
        local.set 6
        local.get 4
        local.set 7
      end
      i32.const 1
      local.set 3
      block  ;; label = @2
        local.get 8
        call $sgx_ocalloc
        local.tee 9
        i32.eqz
        br_if 0 (;@2;)
        local.get 9
        i64.extend_i32_u
        i64.const 24
        i64.add
        local.tee 8
        i32.wrap_i64
        local.set 10
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 9
            local.get 10
            i32.store
            local.get 10
            local.get 7
            local.get 0
            local.get 4
            call $memcpy_s
            br_if 2 (;@2;)
            local.get 8
            local.get 4
            i64.add
            i32.wrap_i64
            local.set 10
            br 1 (;@3;)
          end
          local.get 9
          i32.const 0
          i32.store
          local.get 7
          local.set 6
        end
        block  ;; label = @3
          block  ;; label = @4
            local.get 5
            br_if 0 (;@4;)
            local.get 9
            local.get 10
            i32.store offset=8
            local.get 10
            local.get 6
            local.get 1
            local.get 2
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 9
          i32.const 0
          i32.store offset=8
        end
        local.get 9
        local.get 2
        i64.store offset=16
        i32.const 0
        local.get 9
        call $sgx_ocall
        local.set 3
      end
      call $sgx_ocfree
    end
    local.get 3)
  (func $ocall_write_out (type 2) (param i32 i64) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          br_if 0 (;@3;)
          i64.const 0
          local.set 2
          br 1 (;@2;)
        end
        i32.const 2
        local.set 3
        local.get 0
        local.get 1
        call $sgx_is_within_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        local.set 2
        local.get 1
        i64.const -17
        i64.gt_u
        br_if 1 (;@1;)
      end
      i32.const 1
      local.set 3
      block  ;; label = @2
        local.get 2
        i64.const 16
        i64.add
        call $sgx_ocalloc
        local.tee 4
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 4
            local.get 4
            i32.const 16
            i32.add
            local.tee 5
            i32.store
            local.get 5
            local.get 2
            local.get 0
            local.get 1
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 4
          i32.const 0
          i32.store
        end
        local.get 4
        local.get 1
        i64.store offset=8
        i32.const 1
        local.get 4
        call $sgx_ocall
        local.set 3
      end
      call $sgx_ocfree
    end
    local.get 3)
  (func $ocall_print_raw (type 2) (param i32 i64) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          br_if 0 (;@3;)
          i64.const 0
          local.set 2
          br 1 (;@2;)
        end
        i32.const 2
        local.set 3
        local.get 0
        local.get 1
        call $sgx_is_within_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        local.set 2
        local.get 1
        i64.const -17
        i64.gt_u
        br_if 1 (;@1;)
      end
      i32.const 1
      local.set 3
      block  ;; label = @2
        local.get 2
        i64.const 16
        i64.add
        call $sgx_ocalloc
        local.tee 4
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 4
            local.get 4
            i32.const 16
            i32.add
            local.tee 5
            i32.store
            local.get 5
            local.get 2
            local.get 0
            local.get 1
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 4
          i32.const 0
          i32.store
        end
        local.get 4
        local.get 1
        i64.store offset=8
        i32.const 2
        local.get 4
        call $sgx_ocall
        local.set 3
      end
      call $sgx_ocfree
    end
    local.get 3)
  (func $ocall_print_string (type 15) (param i32) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          br_if 0 (;@3;)
          i64.const 0
          local.set 1
          br 1 (;@2;)
        end
        i32.const 2
        local.set 2
        local.get 0
        local.get 0
        call $strlen
        i64.const 1
        i64.add
        local.tee 1
        call $sgx_is_within_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 1
        i64.const -9
        i64.gt_u
        br_if 1 (;@1;)
      end
      i32.const 1
      local.set 2
      block  ;; label = @2
        local.get 1
        i64.const 8
        i64.add
        call $sgx_ocalloc
        local.tee 3
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 3
            local.get 3
            i32.const 8
            i32.add
            local.tee 4
            i32.store
            local.get 4
            local.get 1
            local.get 0
            local.get 1
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 3
          i32.const 0
          i32.store
        end
        i32.const 3
        local.get 3
        call $sgx_ocall
        local.set 2
      end
      call $sgx_ocfree
    end
    local.get 2)
  (func $sgx_CryptStore_allocStore__ (type 10) (result i32)
    (local i32 i32)
    i64.const 32
    call $malloc
    local.tee 0
    i32.const 0
    i32.store16
    i64.const 4
    call $malloc
    local.set 1
    local.get 0
    i32.const 0
    i32.store offset=8
    local.get 0
    local.get 1
    i32.store offset=4
    local.get 0
    i64.const 1
    call $malloc
    i32.store offset=12
    local.get 0)
  (func $sgx_CryptStore_freeStore_sgx_CryptStore_Store*_ (type 1) (param i32)
    local.get 0
    i32.load offset=4
    call $free
    local.get 0
    i32.load offset=12
    call $free
    local.get 0
    call $free)
  (func $sgx_CryptStore_allocCryptData_unsigned_char_const__*___16___unsigned_char_const*_ (type 7) (param i32 i32) (result i32)
    (local i32)
    i64.const 16
    call $malloc
    local.tee 2
    local.get 1
    i32.store offset=4
    local.get 2
    local.get 0
    i32.store
    local.get 2)
  (func $sgx_CryptStore_freeCryptData_sgx_CryptStore_CryptData*_ (type 1) (param i32)
    local.get 0
    call $free)
  (func $sgx_CryptStore_add_sgx_CryptStore_Store*__void*__unsigned_long_ (type 11) (param i32 i32 i64) (result i32)
    (local i32 i32)
    local.get 0
    local.get 0
    i32.load offset=4
    local.get 0
    i64.load16_u
    i64.const 2
    i64.shl
    i64.const 4
    i64.add
    call $realloc
    local.tee 3
    i32.store offset=4
    local.get 0
    local.get 0
    i32.load16_u
    local.tee 4
    i32.const 1
    i32.add
    i32.store16
    local.get 3
    local.get 4
    i32.const 2
    i32.shl
    i32.add
    local.get 0
    i32.load offset=8
    local.tee 3
    i32.store
    local.get 0
    local.get 0
    i32.load offset=12
    local.get 3
    i64.extend_i32_u
    local.get 2
    i64.add
    call $realloc
    local.tee 3
    i32.store offset=12
    local.get 3
    local.get 0
    i32.load offset=8
    local.tee 4
    i32.add
    local.get 1
    local.get 2
    i32.wrap_i64
    local.tee 3
    call $memcpy
    drop
    local.get 0
    local.get 4
    local.get 3
    i32.add
    i32.store offset=8
    local.get 0
    i32.load16_u
    i32.const -1
    i32.add
    i32.const 65535
    i32.and)
  (func $sgx_CryptStore_get_sgx_CryptStore_Store*__unsigned_long__void*_ (type 12) (param i32 i64 i32) (result i32)
    (local i32 i64 i32)
    i32.const 0
    local.set 3
    block  ;; label = @1
      local.get 0
      i64.load16_u
      local.tee 4
      local.get 1
      i64.le_u
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i64.const -1
          i64.add
          local.get 1
          i64.ne
          br_if 0 (;@3;)
          local.get 0
          i32.load offset=8
          local.get 0
          i32.load offset=4
          local.get 1
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          local.tee 3
          i32.sub
          local.set 5
          br 1 (;@2;)
        end
        local.get 0
        i32.load offset=4
        local.get 1
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        local.tee 3
        i32.const 4
        i32.add
        i32.load
        local.get 3
        i32.load
        local.tee 3
        i32.sub
        local.set 5
      end
      local.get 2
      local.get 0
      i32.load offset=12
      local.get 3
      i32.add
      local.get 5
      call $memcpy
      drop
      i32.const 1
      local.set 3
    end
    local.get 3)
  (func $sgx_CryptStore_toBytes_sgx_CryptStore_Store*__unsigned_long*_ (type 7) (param i32 i32) (result i32)
    (local i32 i64 i64 i32 i64 i32)
    local.get 0
    i32.load16_u
    local.tee 2
    i64.extend_i32_u
    i64.const 65535
    i64.and
    i64.const 2
    i64.shl
    local.tee 3
    i64.const 6
    i64.add
    local.tee 4
    local.get 0
    i32.load offset=8
    local.tee 5
    i64.extend_i32_u
    i64.add
    local.tee 6
    call $malloc
    local.tee 7
    local.get 2
    i32.store16
    local.get 7
    i32.const 2
    i32.add
    local.get 0
    i32.load offset=4
    local.get 3
    i32.wrap_i64
    local.tee 2
    call $memcpy
    drop
    local.get 7
    local.get 2
    i32.add
    i32.const 2
    i32.add
    local.get 5
    i32.store align=2
    local.get 7
    local.get 4
    i32.wrap_i64
    i32.add
    local.get 0
    i32.load offset=12
    local.get 5
    call $memcpy
    drop
    local.get 1
    local.get 6
    i64.store
    local.get 7)
  (func $sgx_CryptStore_fromBytes_sgx_CryptStore_Store*__unsigned_char*_ (type 13) (param i32 i32)
    (local i32 i64 i32)
    local.get 0
    local.get 1
    i32.load16_u
    local.tee 2
    i32.store16
    local.get 0
    local.get 0
    i32.load offset=4
    local.get 2
    i64.extend_i32_u
    i64.const 65535
    i64.and
    i64.const 2
    i64.shl
    local.tee 3
    call $realloc
    local.tee 2
    i32.store offset=4
    local.get 2
    local.get 1
    i32.const 2
    i32.add
    local.tee 1
    local.get 3
    i32.wrap_i64
    local.tee 4
    call $memcpy
    drop
    local.get 0
    local.get 1
    local.get 4
    i32.add
    local.tee 1
    i32.load
    local.tee 2
    i32.store offset=8
    local.get 0
    local.get 0
    i32.load offset=12
    local.get 2
    i64.extend_i32_u
    call $realloc
    local.tee 2
    i32.store offset=12
    local.get 2
    local.get 1
    i32.const 4
    i32.add
    local.get 0
    i32.load offset=8
    call $memcpy
    drop)
  (func $sgx_CryptStore_encrypt_sgx_CryptStore_CryptData*__sgx_CryptStore_Store*__unsigned_long*_ (type 3) (param i32 i32 i32) (result i32)
    (local i32 i64 i64 i32 i64 i32)
    local.get 1
    i32.load16_u
    local.tee 3
    i64.extend_i32_u
    i64.const 65535
    i64.and
    i64.const 2
    i64.shl
    local.tee 4
    i64.const 6
    i64.add
    local.tee 5
    local.get 1
    i32.load offset=8
    local.tee 6
    i64.extend_i32_u
    i64.add
    local.tee 7
    call $malloc
    local.tee 8
    local.get 3
    i32.store16
    local.get 8
    i32.const 2
    i32.add
    local.get 1
    i32.load offset=4
    local.get 4
    i32.wrap_i64
    local.tee 3
    call $memcpy
    drop
    local.get 8
    local.get 3
    i32.add
    i32.const 2
    i32.add
    local.get 6
    i32.store align=2
    local.get 8
    local.get 5
    i32.wrap_i64
    i32.add
    local.get 1
    i32.load offset=12
    local.get 6
    call $memcpy
    drop
    local.get 7
    i64.const 16
    i64.add
    local.tee 4
    call $malloc
    local.set 1
    local.get 0
    i32.load
    local.get 8
    local.get 7
    i32.wrap_i64
    local.tee 6
    local.get 1
    local.get 0
    i32.load offset=4
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 1
    local.get 6
    i32.add
    call $sgx_rijndael128GCM_encrypt
    local.set 0
    local.get 8
    call $free
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      call $free
      i32.const 0
      return
    end
    local.get 2
    local.get 4
    i64.store
    local.get 1)
  (func $sgx_CryptStore_decrypt_sgx_CryptStore_CryptData*__sgx_CryptStore_Store*__unsigned_char*__unsigned_long_ (type 14) (param i32 i32 i32 i64) (result i32)
    (local i32 i32 i32)
    local.get 3
    i64.const -16
    i64.add
    local.tee 3
    call $malloc
    local.set 4
    block  ;; label = @1
      local.get 0
      i32.load
      local.get 2
      local.get 3
      i32.wrap_i64
      local.tee 5
      local.get 4
      local.get 0
      i32.load offset=4
      i32.const 12
      i32.const 0
      i32.const 0
      local.get 2
      local.get 5
      i32.add
      call $sgx_rijndael128GCM_decrypt
      local.tee 0
      br_if 0 (;@1;)
      local.get 1
      local.get 4
      i32.load16_u
      local.tee 2
      i32.store16
      local.get 1
      local.get 1
      i32.load offset=4
      local.get 2
      i64.extend_i32_u
      i64.const 65535
      i64.and
      i64.const 2
      i64.shl
      local.tee 3
      call $realloc
      local.tee 2
      i32.store offset=4
      local.get 2
      local.get 4
      i32.const 2
      i32.add
      local.tee 5
      local.get 3
      i32.wrap_i64
      local.tee 6
      call $memcpy
      drop
      local.get 1
      local.get 5
      local.get 6
      i32.add
      local.tee 2
      i32.load
      local.tee 5
      i32.store offset=8
      local.get 1
      local.get 1
      i32.load offset=12
      local.get 5
      i64.extend_i32_u
      call $realloc
      local.tee 5
      i32.store offset=12
      local.get 5
      local.get 2
      i32.const 4
      i32.add
      local.get 1
      i32.load offset=8
      call $memcpy
      drop
    end
    local.get 4
    call $free
    local.get 0)
  (func $printf_char_const*__..._ (type 13) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 8224
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=8220
    local.get 2
    i32.const 16
    i32.add
    i32.const 0
    i32.const 8192
    call $memset
    drop
    local.get 2
    local.get 1
    i32.store
    local.get 2
    i32.const 16
    i32.add
    i64.const 8192
    local.get 0
    local.get 2
    call $vsnprintf
    drop
    local.get 2
    i32.const 16
    i32.add
    call $ocall_print_string
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=8220
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 8224
    i32.add
    global.set $__stack_pointer)
  (table (;0;) 8 8 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66720))
  (global (;1;) i32 (i32.const 1168))
  (global (;2;) i32 (i32.const 1024))
  (global (;3;) i32 (i32.const 1088))
  (global (;4;) i32 (i32.const 1024))
  (global (;5;) i32 (i32.const 1172))
  (global (;6;) i32 (i32.const 1024))
  (global (;7;) i32 (i32.const 66720))
  (global (;8;) i32 (i32.const 0))
  (global (;9;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "sgx_CryptStore_allocStore" (func $sgx_CryptStore_allocStore))
  (export "sgx_CryptStore_freeStore" (func $sgx_CryptStore_freeStore))
  (export "sgx_CryptStore_allocCryptData" (func $sgx_CryptStore_allocCryptData))
  (export "sgx_CryptStore_freeCryptData" (func $sgx_CryptStore_freeCryptData))
  (export "sgx_CryptStore_add" (func $sgx_CryptStore_add))
  (export "sgx_CryptStore_get" (func $sgx_CryptStore_get))
  (export "sgx_CryptStore_toBytes" (func $sgx_CryptStore_toBytes))
  (export "sgx_CryptStore_fromBytes" (func $sgx_CryptStore_fromBytes))
  (export "sgx_CryptStore_encrypt" (func $sgx_CryptStore_encrypt))
  (export "sgx_CryptStore_decrypt" (func $sgx_CryptStore_decrypt))
  (export "init_store" (func $init_store))
  (export "free_store" (func $free_store))
  (export "add_to_store" (func $add_to_store))
  (export "get_from_store" (func $get_from_store))
  (export "encrypt_store" (func $encrypt_store))
  (export "decrypt_store" (func $decrypt_store))
  (export "store_to_bytes" (func $store_to_bytes))
  (export "ocall_write_resource" (func $ocall_write_resource))
  (export "ocall_write_out" (func $ocall_write_out))
  (export "ocall_print_raw" (func $ocall_print_raw))
  (export "ocall_print_string" (func $ocall_print_string))
  (export "_Z25sgx_CryptStore_allocStorev" (func $sgx_CryptStore_allocStore__))
  (export "_Z24sgx_CryptStore_freeStoreP20sgx_CryptStore_Store" (func $sgx_CryptStore_freeStore_sgx_CryptStore_Store*_))
  (export "_Z29sgx_CryptStore_allocCryptDataPA16_KhPS_" (func $sgx_CryptStore_allocCryptData_unsigned_char_const__*___16___unsigned_char_const*_))
  (export "_Z28sgx_CryptStore_freeCryptDataP24sgx_CryptStore_CryptData" (func $sgx_CryptStore_freeCryptData_sgx_CryptStore_CryptData*_))
  (export "_Z18sgx_CryptStore_addP20sgx_CryptStore_StorePvm" (func $sgx_CryptStore_add_sgx_CryptStore_Store*__void*__unsigned_long_))
  (export "_Z18sgx_CryptStore_getP20sgx_CryptStore_StoremPv" (func $sgx_CryptStore_get_sgx_CryptStore_Store*__unsigned_long__void*_))
  (export "_Z22sgx_CryptStore_toBytesP20sgx_CryptStore_StorePm" (func $sgx_CryptStore_toBytes_sgx_CryptStore_Store*__unsigned_long*_))
  (export "_Z24sgx_CryptStore_fromBytesP20sgx_CryptStore_StorePh" (func $sgx_CryptStore_fromBytes_sgx_CryptStore_Store*__unsigned_char*_))
  (export "_Z22sgx_CryptStore_encryptP24sgx_CryptStore_CryptDataP20sgx_CryptStore_StorePm" (func $sgx_CryptStore_encrypt_sgx_CryptStore_CryptData*__sgx_CryptStore_Store*__unsigned_long*_))
  (export "_Z22sgx_CryptStore_decryptP24sgx_CryptStore_CryptDataP20sgx_CryptStore_StorePhm" (func $sgx_CryptStore_decrypt_sgx_CryptStore_CryptData*__sgx_CryptStore_Store*__unsigned_char*__unsigned_long_))
  (export "_Z6printfPKcz" (func $printf_char_const*__..._))
  (export "store" (global 1))
  (export "g_ecall_table" (global 2))
  (export "g_dyn_entry_table" (global 3))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 4))
  (export "__data_end" (global 5))
  (export "__global_base" (global 6))
  (export "__heap_base" (global 7))
  (export "__memory_base" (global 8))
  (export "__table_base" (global 9))
  (elem (;0;) (i32.const 1) func $sgx_init_store $sgx_free_store $sgx_add_to_store $sgx_get_from_store $sgx_encrypt_store $sgx_decrypt_store $sgx_store_to_bytes)
  (data $.rodata (i32.const 1024) "\07\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\05\00\00\00\00\00\00\00\06\00\00\00\00\00\00\00\07\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f\10\01\02\03\04\05\06\07\08\09\0a\0b\0c"))
