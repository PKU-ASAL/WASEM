(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32 i32 i32) (result i32)))
  (type (;4;) (func (param i32)))
  (type (;5;) (func (param i32) (result i64)))
  (type (;6;) (func (param i32 i32) (result i32)))
  (type (;7;) (func))
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
  (import "env" "sgx_ocall" (func $sgx_ocall (type 6)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 7)))
  (import "env" "sgx_rijndael128GCM_decrypt" (func $sgx_rijndael128GCM_decrypt (type 8)))
  (import "env" "memcpy" (func $memcpy (type 3)))
  (import "env" "__stack_chk_fail" (func $__stack_chk_fail (type 7)))
  (import "env" "sgx_read_rand" (func $sgx_read_rand (type 0)))
  (import "env" "sgx_rijndael128GCM_encrypt" (func $sgx_rijndael128GCM_encrypt (type 8)))
  (func $__wasm_call_ctors (type 7))
  (func $sgx_sgxDecryptFile (type 9) (param i32) (result i32)
    (local i32 i64 i32 i64 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 32
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=24
      local.set 2
      local.get 0
      i32.load offset=16
      local.set 3
      local.get 0
      i64.load offset=8
      local.set 4
      block  ;; label = @2
        local.get 0
        i32.load
        local.tee 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 4
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        local.get 2
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 5
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 4
            i64.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 4
              call $malloc
              local.tee 5
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 5
            local.get 4
            local.get 0
            local.get 4
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 1
            i32.const 0
            local.set 0
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                local.get 3
                i32.eqz
                br_if 0 (;@6;)
                local.get 2
                i64.const 0
                i64.ne
                br_if 1 (;@5;)
              end
              i32.const 0
              local.set 1
              local.get 5
              local.get 4
              i32.const 0
              local.get 2
              call $sgxDecryptFile
              i32.const 0
              local.set 0
              br 1 (;@4;)
            end
            block  ;; label = @5
              local.get 2
              call $malloc
              local.tee 0
              br_if 0 (;@5;)
              i32.const 0
              local.set 0
              i32.const 3
              local.set 1
              br 1 (;@4;)
            end
            local.get 5
            local.get 4
            local.get 0
            i32.const 0
            local.get 2
            i32.wrap_i64
            call $memset
            local.tee 1
            local.get 2
            call $sgxDecryptFile
            local.get 3
            local.get 2
            local.get 1
            local.get 2
            call $memcpy_s
            i32.const 0
            i32.ne
            local.set 1
          end
          local.get 5
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 5
        call $free
      end
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      call $free
    end
    local.get 1)
  (func $sgxDecryptFile (type 10) (param i32 i64 i32 i64)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.tee 5
    i32.const 0
    i32.load
    i32.store offset=12
    local.get 4
    local.get 3
    i32.wrap_i64
    local.tee 6
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    i32.const 1489
    call $printDebug
    drop
    block  ;; label = @1
      i32.const 1568
      local.get 0
      i32.const 28
      i32.add
      local.get 6
      local.get 4
      local.get 0
      i32.const 16
      i32.add
      i32.const 12
      i32.const 0
      i32.const 0
      local.get 0
      call $sgx_rijndael128GCM_decrypt
      local.tee 0
      i32.const 3
      i32.gt_u
      br_if 0 (;@1;)
      local.get 0
      i32.const 2
      i32.shl
      i32.const 1516
      i32.add
      i32.load
      i32.const 1516
      i32.add
      call $printDebug
      drop
    end
    local.get 2
    local.get 4
    local.get 6
    call $memcpy
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 5
      i32.load offset=12
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 5
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_sgxEncryptFile (type 9) (param i32) (result i32)
    (local i32 i64 i32 i64 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 32
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load offset=24
      local.set 2
      local.get 0
      i32.load offset=16
      local.set 3
      local.get 0
      i64.load offset=8
      local.set 4
      block  ;; label = @2
        local.get 0
        i32.load
        local.tee 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 4
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        local.get 2
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 5
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 4
            i64.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 4
              call $malloc
              local.tee 5
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 5
            local.get 4
            local.get 0
            local.get 4
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 1
            i32.const 0
            local.set 0
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                local.get 3
                i32.eqz
                br_if 0 (;@6;)
                local.get 2
                i64.const 0
                i64.ne
                br_if 1 (;@5;)
              end
              i32.const 0
              local.set 1
              local.get 5
              local.get 4
              i32.const 0
              local.get 2
              call $sgxEncryptFile
              i32.const 0
              local.set 0
              br 1 (;@4;)
            end
            block  ;; label = @5
              local.get 2
              call $malloc
              local.tee 0
              br_if 0 (;@5;)
              i32.const 0
              local.set 0
              i32.const 3
              local.set 1
              br 1 (;@4;)
            end
            local.get 5
            local.get 4
            local.get 0
            i32.const 0
            local.get 2
            i32.wrap_i64
            call $memset
            local.tee 1
            local.get 2
            call $sgxEncryptFile
            local.get 3
            local.get 2
            local.get 1
            local.get 2
            call $memcpy_s
            i32.const 0
            i32.ne
            local.set 1
          end
          local.get 5
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 5
        call $free
      end
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      call $free
    end
    local.get 1)
  (func $sgxEncryptFile (type 10) (param i32 i64 i32 i64)
    (local i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.tee 5
    i32.const 0
    i32.load
    i32.store offset=12
    local.get 4
    local.get 3
    i32.wrap_i64
    local.tee 6
    i32.const 15
    i32.add
    i32.const -16
    i32.and
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    i32.const 1462
    call $printDebug
    drop
    block  ;; label = @1
      local.get 4
      i32.const 16
      i32.add
      local.tee 7
      i64.const 12
      call $sgx_read_rand
      local.tee 8
      i32.const 2
      i32.gt_u
      br_if 0 (;@1;)
      local.get 8
      i32.const 2
      i32.shl
      i32.const 1532
      i32.add
      i32.load
      i32.const 1532
      i32.add
      call $printDebug
      drop
    end
    block  ;; label = @1
      i32.const 1568
      local.get 0
      local.get 1
      i32.wrap_i64
      local.get 4
      i32.const 28
      i32.add
      local.get 7
      i32.const 12
      i32.const 0
      i32.const 0
      local.get 4
      call $sgx_rijndael128GCM_encrypt
      local.tee 0
      i32.const 3
      i32.gt_u
      br_if 0 (;@1;)
      local.get 0
      i32.const 2
      i32.shl
      i32.const 1544
      i32.add
      i32.load
      i32.const 1544
      i32.add
      call $printDebug
      drop
    end
    local.get 2
    local.get 4
    local.get 6
    call $memcpy
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 5
      i32.load offset=12
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 5
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $printDebug (type 9) (param i32) (result i32)
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
        i32.const 0
        local.get 3
        call $sgx_ocall
        local.set 2
      end
      call $sgx_ocfree
    end
    local.get 2)
  (table (;0;) 3 3 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 67120))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1048))
  (global (;3;) i32 (i32.const 1024))
  (global (;4;) i32 (i32.const 1584))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 67120))
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
  (data $.rodata (i32.const 1024) "\02\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00ENCRYPT RESULT: SGX_ERROR_OUT_OF_MEMORY\00DECRYPT RESULT: SGX_ERROR_OUT_OF_MEMORY\00ENCRYPT RESULT: SGX_SUCCESS\00DECRYPT RESULT: SGX_SUCCESS\00RAND RESULT: SGX_SUCCESS\00ENCRYPT RESULT: SGX_ERROR_INVALID_PARAMETER\00DECRYPT RESULT: SGX_ERROR_INVALID_PARAMETER\00RAND RESULT: SGX_ERROR_INVALID_PARAMETER\00ENCRYPT RESULT: SGX_ERROR_UNEXPECTED\00DECRYPT RESULT: SGX_ERROR_UNEXPECTED\00RAND RESULT: SGX_ERROR_UNEXPECTED\00INIT ENCLAVE ENCRYPTION...\00INIT ENCLAVE DECRYPTION...\00\a8\fe\ff\ff\83\ff\ff\ff\09\ff\ff\ffd\fe\ff\ff\b4\fe\ff\ff\98\ff\ff\ff%\ff\ff\ffp\fe\ff\ffB\ff\ff\ff\c1\fe\ff\ff \fe\ff\ff")
  (data $.data (i32.const 1568) "\00\01\02\03\04\05\06\07\08\09\0a\0b\0c\0d\0e\0f"))
