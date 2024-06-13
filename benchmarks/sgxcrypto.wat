(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32 i32 i32) (result i32)))
  (type (;4;) (func (param i32)))
  (type (;5;) (func (param i32) (result i64)))
  (type (;6;) (func))
  (type (;7;) (func (param i32 i32) (result i32)))
  (type (;8;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;9;) (func (param i32) (result i32)))
  (type (;10;) (func (param i32 i64 i32 i64)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "malloc" (func $malloc (type 1)))
  (import "env" "memcpy_s" (func $memcpy_s (type 2)))
  (import "env" "memset" (func $memset (type 3)))
  (import "env" "free" (func $free (type 4)))
  (import "env" "strlen" (func $strlen (type 5)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 1)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 6)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 7)))
  (import "env" "sgx_rijndael128GCM_decrypt" (func $sgx_rijndael128GCM_decrypt (type 8)))
  (import "env" "memcpy" (func $memcpy (type 3)))
  (import "env" "sgx_read_rand" (func $sgx_read_rand (type 0)))
  (import "env" "sgx_rijndael128GCM_encrypt" (func $sgx_rijndael128GCM_encrypt (type 8)))
  (func $__wasm_call_ctors (type 6))
  (func $sgx_sgxDecryptFile (type 9) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=72
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=72
          i64.const 32
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=72
      i32.store offset=64
      local.get 1
      i32.const 0
      i32.store offset=60
      local.get 1
      local.get 1
      i32.load offset=64
      i32.load
      i32.store offset=56
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=8
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
      i32.load offset=64
      i32.load offset=16
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=24
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
        i32.store offset=76
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
        i32.store offset=76
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
            i32.store offset=60
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
            i32.store offset=60
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
            i32.store offset=60
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
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          local.tee 0
          i32.store
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
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          i32.load
          i32.const 0
          local.get 1
          i64.load offset=8
          i32.wrap_i64
          call $memset
          drop
        end
        local.get 1
        i32.load offset=32
        local.get 1
        i64.load offset=48
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $sgxDecryptFile
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
            i32.store offset=60
            br 2 (;@2;)
          end
        end
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
      i32.load offset=60
      i32.store offset=76
    end
    local.get 1
    i32.load offset=76
    local.set 0
    local.get 1
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $sgxDecryptFile (type 10) (param i32 i64 i32 i64)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.tee 5
    local.get 0
    i32.store offset=56
    local.get 5
    local.get 1
    i64.store offset=48
    local.get 5
    local.get 2
    i32.store offset=40
    local.get 5
    local.get 3
    i64.store offset=32
    local.get 5
    local.get 5
    i32.load offset=56
    i32.store offset=24
    local.get 5
    i64.load offset=32
    local.set 3
    local.get 5
    local.get 4
    i32.store offset=16
    local.get 4
    local.get 3
    i32.wrap_i64
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 5
    local.get 3
    i64.store offset=8
    i32.const 1489
    call $printDebug
    drop
    local.get 5
    i32.const 1520
    local.get 5
    i32.load offset=24
    i32.const 16
    i32.add
    i32.const 12
    i32.add
    local.get 5
    i64.load offset=32
    i32.wrap_i64
    local.get 4
    local.get 5
    i32.load offset=24
    i32.const 16
    i32.add
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 5
    i32.load offset=24
    call $sgx_rijndael128GCM_decrypt
    i32.store offset=4
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      br_if 0 (;@1;)
      i32.const 1172
      call $printDebug
      drop
    end
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      i32.const 2
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1269
      call $printDebug
      drop
    end
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      i32.const 3
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1104
      call $printDebug
      drop
    end
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      i32.const 1
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1391
      call $printDebug
      drop
    end
    local.get 5
    i32.load offset=40
    local.get 4
    local.get 5
    i64.load offset=32
    i32.wrap_i64
    call $memcpy
    drop
    local.get 5
    i32.load offset=16
    drop
    local.get 5
    i32.const 64
    i32.add
    global.set $__stack_pointer)
  (func $sgx_sgxEncryptFile (type 9) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=72
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=72
          i64.const 32
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=72
      i32.store offset=64
      local.get 1
      i32.const 0
      i32.store offset=60
      local.get 1
      local.get 1
      i32.load offset=64
      i32.load
      i32.store offset=56
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=8
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
      i32.load offset=64
      i32.load offset=16
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=24
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
        i32.store offset=76
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
        i32.store offset=76
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
            i32.store offset=60
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
            i32.store offset=60
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
            i32.store offset=60
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
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          local.get 1
          i64.load offset=8
          call $malloc
          local.tee 0
          i32.store
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
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          i32.load
          i32.const 0
          local.get 1
          i64.load offset=8
          i32.wrap_i64
          call $memset
          drop
        end
        local.get 1
        i32.load offset=32
        local.get 1
        i64.load offset=48
        local.get 1
        i32.load
        local.get 1
        i64.load offset=16
        call $sgxEncryptFile
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
            i32.store offset=60
            br 2 (;@2;)
          end
        end
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
      i32.load offset=60
      i32.store offset=76
    end
    local.get 1
    i32.load offset=76
    local.set 0
    local.get 1
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $sgxEncryptFile (type 10) (param i32 i64 i32 i64)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.tee 5
    local.get 0
    i32.store offset=56
    local.get 5
    local.get 1
    i64.store offset=48
    local.get 5
    local.get 2
    i32.store offset=40
    local.get 5
    local.get 3
    i64.store offset=32
    local.get 5
    local.get 5
    i32.load offset=56
    i32.store offset=24
    local.get 5
    i64.load offset=32
    local.set 3
    local.get 5
    local.get 4
    i32.store offset=16
    local.get 4
    local.get 3
    i32.wrap_i64
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 5
    local.get 3
    i64.store offset=8
    i32.const 1462
    call $printDebug
    drop
    local.get 5
    local.get 4
    i32.const 16
    i32.add
    i64.const 12
    call $sgx_read_rand
    i32.store offset=4
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      br_if 0 (;@1;)
      i32.const 1200
      call $printDebug
      drop
    end
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      i32.const 2
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1313
      call $printDebug
      drop
    end
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      i32.const 1
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1428
      call $printDebug
      drop
    end
    local.get 5
    i32.const 1520
    local.get 5
    i32.load offset=24
    local.get 5
    i64.load offset=48
    i32.wrap_i64
    local.get 4
    i32.const 16
    i32.add
    i32.const 12
    i32.add
    local.get 4
    i32.const 16
    i32.add
    i32.const 12
    i32.const 0
    i32.const 0
    local.get 4
    call $sgx_rijndael128GCM_encrypt
    i32.store offset=4
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      br_if 0 (;@1;)
      i32.const 1144
      call $printDebug
      drop
    end
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      i32.const 2
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1225
      call $printDebug
      drop
    end
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      i32.const 3
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1064
      call $printDebug
      drop
    end
    block  ;; label = @1
      local.get 5
      i32.load offset=4
      i32.const 1
      i32.eq
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      i32.const 1354
      call $printDebug
      drop
    end
    local.get 5
    i32.load offset=40
    local.get 4
    local.get 5
    i64.load offset=32
    i32.wrap_i64
    call $memcpy
    drop
    local.get 5
    i32.load offset=16
    drop
    local.get 5
    i32.const 64
    i32.add
    global.set $__stack_pointer)
  (func $printDebug (type 9) (param i32) (result i32)
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
  (table (;0;) 3 3 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 67072))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1048))
  (global (;3;) i32 (i32.const 1024))
  (global (;4;) i32 (i32.const 1536))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 67072))
  (global (;7;) i32 (i32.const 0))
  (global (;8;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "sgxDecryptFile" (func $sgxDecryptFile))
  (export "sgxEncryptFile" (func $sgxEncryptFile))
  (export "printDebug" (func $printDebug))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 3))
  (export "__data_end" (global 4))
  (export "__global_base" (global 5))
  (export "__heap_base" (global 6))
  (export "__memory_base" (global 7))
  (export "__table_base" (global 8))
  (elem (;0;) (i32.const 1) func $sgx_sgxDecryptFile $sgx_sgxEncryptFile)
  (data $.rodata (i32.const 1024) "\02\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00ENCRYPT RESULT: SGX_ERROR_OUT_OF_MEMORY\00DECRYPT RESULT: SGX_ERROR_OUT_OF_MEMORY\00ENCRYPT RESULT: SGX_SUCCESS\00DECRYPT RESULT: SGX_SUCCESS\00RAND RESULT: SGX_SUCCESS\00ENCRYPT RESULT: SGX_ERROR_INVALID_PARAMETER\00DECRYPT RESULT: SGX_ERROR_INVALID_PARAMETER\00RAND RESULT: SGX_ERROR_INVALID_PARAMETER\00ENCRYPT RESULT: SGX_ERROR_UNEXPECTED\00DECRYPT RESULT: SGX_ERROR_UNEXPECTED\00RAND RESULT: SGX_ERROR_UNEXPECTED\00INIT ENCLAVE ENCRYPTION...\00INIT ENCLAVE DECRYPTION...\00")
  (data $.data (i32.const 1520) "\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f"))
