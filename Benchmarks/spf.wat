(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32) (result i64)))
  (type (;4;) (func (param i32)))
  (type (;5;) (func))
  (type (;6;) (func (param i32 i32) (result i32)))
  (type (;7;) (func (param i32 i32 i32) (result i32)))
  (type (;8;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;9;) (func (param i32 i64 i64 i32) (result i64)))
  (type (;10;) (func (param i32) (result i32)))
  (type (;11;) (func (param i32 i32 i32 i64) (result i32)))
  (type (;12;) (func (param i32 i32 i64) (result i32)))
  (type (;13;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;14;) (func (param i32 i32 i64 i32 i32) (result i32)))
  (type (;15;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;16;) (func (param i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;17;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;18;) (func (param i32 i32 i64) (result i64)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "malloc" (func $malloc (type 1)))
  (import "env" "memcpy_s" (func $memcpy_s (type 2)))
  (import "env" "strlen" (func $strlen (type 3)))
  (import "env" "free" (func $free (type 4)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 1)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 5)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 6)))
  (import "env" "memset" (func $memset (type 7)))
  (import "env" "vsnprintf" (func $vsnprintf (type 8)))
  (import "env" "__stack_chk_fail" (func $__stack_chk_fail (type 5)))
  (import "env" "sgx_fopen" (func $sgx_fopen (type 7)))
  (import "env" "sgx_fwrite" (func $sgx_fwrite (type 9)))
  (import "env" "sgx_fclose" (func $sgx_fclose (type 10)))
  (import "env" "sgx_fread" (func $sgx_fread (type 9)))
  (func $__wasm_call_ctors (type 5))
  (func $sgx_ecall_encrypt_file (type 10) (param i32) (result i32)
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
          i64.const 48
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
      i32.load offset=4
      i32.store offset=56
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=8
      i64.store offset=48
      local.get 1
      i32.const 0
      i32.store offset=40
      local.get 1
      local.get 1
      i32.load offset=64
      i32.load offset=16
      i32.store offset=32
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=24
      i64.store offset=24
      local.get 1
      i32.const 0
      i32.store offset=16
      local.get 1
      local.get 1
      i32.load offset=64
      i32.load offset=32
      i32.store offset=8
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
        i64.load offset=48
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
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
        local.get 1
        i64.load offset=24
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
          i64.load offset=48
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=48
          call $malloc
          i32.store offset=40
          block  ;; label = @4
            local.get 1
            i32.load offset=40
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
            i32.load offset=40
            local.get 1
            i64.load offset=48
            local.get 1
            i32.load offset=56
            local.get 1
            i64.load offset=48
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=40
          local.get 1
          i64.load offset=48
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          block  ;; label = @4
            local.get 1
            i64.load offset=48
            local.get 1
            i32.load offset=40
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
            i32.store offset=60
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=32
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=24
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=24
          call $malloc
          i32.store offset=16
          block  ;; label = @4
            local.get 1
            i32.load offset=16
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
            i32.load offset=16
            local.get 1
            i64.load offset=24
            local.get 1
            i32.load offset=32
            local.get 1
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=16
          local.get 1
          i64.load offset=24
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          block  ;; label = @4
            local.get 1
            i64.load offset=24
            local.get 1
            i32.load offset=16
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
            i32.store offset=60
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=40
        local.get 1
        i32.load offset=16
        local.get 1
        i32.load offset=8
        call $ecall_encrypt_file
        local.set 0
        local.get 1
        i32.load offset=64
        local.get 0
        i32.store
      end
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
        call $free
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=16
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=16
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
  (func $ecall_encrypt_file (type 7) (param i32 i32 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 4176
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    i32.const 0
    i32.load
    i32.store offset=4172
    local.get 3
    local.get 0
    i32.store offset=40
    local.get 3
    local.get 1
    i32.store offset=32
    local.get 3
    local.get 2
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=24
        i64.const 16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 3
        i32.const -1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 3
      i32.const 4144
      i32.add
      local.tee 2
      local.get 3
      i32.load offset=24
      local.tee 1
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 1
      i32.const 8
      i32.add
      i64.load align=1
      i64.store align=1
      local.get 3
      local.get 3
      i32.load offset=40
      call $open_char_const*_
      i32.store offset=20
      block  ;; label = @2
        local.get 3
        i32.load offset=20
        i32.const 0
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.const -1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load offset=32
      i32.const 1112
      local.get 3
      i32.const 4144
      i32.add
      call $sgx_fopen
      i32.store offset=16
      block  ;; label = @2
        local.get 3
        i32.load offset=16
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=20
        call $close_int_
        drop
        local.get 3
        i32.const -1
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        loop  ;; label = @3
          local.get 3
          local.get 3
          i32.load offset=20
          local.get 3
          i32.const 48
          i32.add
          i64.const 4096
          call $read_int__void*__unsigned_long_
          local.tee 4
          i64.store offset=8
          local.get 4
          i64.const 0
          i64.gt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 3
          i32.const 48
          i32.add
          i64.const 1
          local.get 3
          i64.load offset=8
          local.get 3
          i32.load offset=16
          call $sgx_fwrite
          drop
          br 0 (;@3;)
        end
      end
      local.get 3
      i32.load offset=20
      call $close_int_
      drop
      local.get 3
      i32.load offset=16
      call $sgx_fclose
      drop
      local.get 3
      i32.const 0
      i32.store offset=44
    end
    local.get 3
    i32.load offset=44
    local.set 2
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 3
      i32.load offset=4172
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 3
    i32.const 4176
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $sgx_ecall_decrypt_file (type 10) (param i32) (result i32)
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
          i64.const 48
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
      i32.load offset=4
      i32.store offset=56
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=8
      i64.store offset=48
      local.get 1
      i32.const 0
      i32.store offset=40
      local.get 1
      local.get 1
      i32.load offset=64
      i32.load offset=16
      i32.store offset=32
      local.get 1
      local.get 1
      i32.load offset=64
      i64.load offset=24
      i64.store offset=24
      local.get 1
      i32.const 0
      i32.store offset=16
      local.get 1
      local.get 1
      i32.load offset=64
      i32.load offset=32
      i32.store offset=8
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
        i64.load offset=48
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
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
        local.get 1
        i64.load offset=24
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
          i64.load offset=48
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=48
          call $malloc
          i32.store offset=40
          block  ;; label = @4
            local.get 1
            i32.load offset=40
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
            i32.load offset=40
            local.get 1
            i64.load offset=48
            local.get 1
            i32.load offset=56
            local.get 1
            i64.load offset=48
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=40
          local.get 1
          i64.load offset=48
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          block  ;; label = @4
            local.get 1
            i64.load offset=48
            local.get 1
            i32.load offset=40
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
            i32.store offset=60
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=32
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          i64.load offset=24
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=24
          call $malloc
          i32.store offset=16
          block  ;; label = @4
            local.get 1
            i32.load offset=16
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
            i32.load offset=16
            local.get 1
            i64.load offset=24
            local.get 1
            i32.load offset=32
            local.get 1
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=60
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=16
          local.get 1
          i64.load offset=24
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          block  ;; label = @4
            local.get 1
            i64.load offset=24
            local.get 1
            i32.load offset=16
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
            i32.store offset=60
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=40
        local.get 1
        i32.load offset=16
        local.get 1
        i32.load offset=8
        call $ecall_decrypt_file
        local.set 0
        local.get 1
        i32.load offset=64
        local.get 0
        i32.store
      end
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
        call $free
      end
      block  ;; label = @2
        local.get 1
        i32.load offset=16
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=16
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
  (func $ecall_decrypt_file (type 7) (param i32 i32 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 4176
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    i32.const 0
    i32.load
    i32.store offset=4172
    local.get 3
    local.get 0
    i32.store offset=40
    local.get 3
    local.get 1
    i32.store offset=32
    local.get 3
    local.get 2
    i32.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=24
        i64.const 16
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 3
        i32.const -1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 3
      i32.const 4144
      i32.add
      local.tee 2
      local.get 3
      i32.load offset=24
      local.tee 1
      i64.load align=1
      i64.store align=1
      local.get 2
      i32.const 8
      i32.add
      local.get 1
      i32.const 8
      i32.add
      i64.load align=1
      i64.store align=1
      local.get 3
      local.get 3
      i32.load offset=40
      i32.const 1114
      local.get 3
      i32.const 4144
      i32.add
      call $sgx_fopen
      i32.store offset=16
      block  ;; label = @2
        local.get 3
        i32.load offset=16
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.const -1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load offset=32
      call $create_char_const*_
      i32.store offset=12
      block  ;; label = @2
        local.get 3
        i32.load offset=12
        i32.const 0
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=16
        call $sgx_fclose
        drop
        local.get 3
        i32.const -1
        i32.store offset=44
        br 1 (;@1;)
      end
      block  ;; label = @2
        loop  ;; label = @3
          local.get 3
          local.get 3
          i32.const 48
          i32.add
          i64.const 1
          i64.const 4096
          local.get 3
          i32.load offset=16
          call $sgx_fread
          local.tee 4
          i64.store
          local.get 4
          i64.const 0
          i64.gt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 3
          i32.load offset=12
          local.get 3
          i32.const 48
          i32.add
          local.get 3
          i64.load
          call $write_int__void_const*__unsigned_long_
          drop
          br 0 (;@3;)
        end
      end
      local.get 3
      i32.load offset=12
      call $close_int_
      drop
      local.get 3
      i32.load offset=16
      call $sgx_fclose
      drop
      local.get 3
      i32.const 0
      i32.store offset=44
    end
    local.get 3
    i32.load offset=44
    local.set 2
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 3
      i32.load offset=4172
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 3
    i32.const 4176
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $ocall_open (type 6) (param i32 i32) (result i32)
    (local i32 i64)
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
    i32.store offset=48
    local.get 2
    i32.const 0
    i32.store offset=44
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        call $strlen
        i64.const 1
        i64.add
        local.set 3
        br 1 (;@1;)
      end
      i64.const 0
      local.set 3
    end
    local.get 2
    local.get 3
    i64.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 16
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        local.get 2
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 2
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i64.load offset=32
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      local.get 2
      local.get 2
      i64.load offset=16
      local.get 3
      i64.add
      i64.store offset=16
      local.get 2
      local.get 2
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
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
        i32.store offset=60
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
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=24
          local.get 2
          i32.load offset=8
          i32.store offset=4
          block  ;; label = @4
            local.get 2
            i32.load offset=8
            local.get 2
            i64.load offset=16
            local.get 2
            i32.load offset=48
            local.get 2
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 2
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 2
          local.get 2
          i32.load offset=8
          i64.extend_i32_u
          local.get 2
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 2
          local.get 2
          i64.load offset=16
          local.get 2
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 2
        i32.load offset=24
        i32.const 0
        i32.store offset=4
      end
      local.get 2
      i32.const 0
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=44
      block  ;; label = @2
        local.get 2
        i32.load offset=44
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=56
          local.get 2
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=44
      i32.store offset=60
    end
    local.get 2
    i32.load offset=60
    local.set 1
    local.get 2
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $ocall_create (type 6) (param i32 i32) (result i32)
    (local i32 i64)
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
    i32.store offset=48
    local.get 2
    i32.const 0
    i32.store offset=44
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        call $strlen
        i64.const 1
        i64.add
        local.set 3
        br 1 (;@1;)
      end
      i64.const 0
      local.set 3
    end
    local.get 2
    local.get 3
    i64.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 16
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        local.get 2
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 2
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i64.load offset=32
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      local.get 2
      local.get 2
      i64.load offset=16
      local.get 3
      i64.add
      i64.store offset=16
      local.get 2
      local.get 2
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
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
        i32.store offset=60
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
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=24
          local.get 2
          i32.load offset=8
          i32.store offset=4
          block  ;; label = @4
            local.get 2
            i32.load offset=8
            local.get 2
            i64.load offset=16
            local.get 2
            i32.load offset=48
            local.get 2
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 2
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 2
          local.get 2
          i32.load offset=8
          i64.extend_i32_u
          local.get 2
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 2
          local.get 2
          i64.load offset=16
          local.get 2
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 2
        i32.load offset=24
        i32.const 0
        i32.store offset=4
      end
      local.get 2
      i32.const 1
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=44
      block  ;; label = @2
        local.get 2
        i32.load offset=44
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=56
          local.get 2
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=44
      i32.store offset=60
    end
    local.get 2
    i32.load offset=60
    local.set 1
    local.get 2
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $ocall_read (type 11) (param i32 i32 i32 i64) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=72
    local.get 4
    local.get 1
    i32.store offset=68
    local.get 4
    local.get 2
    i32.store offset=64
    local.get 4
    local.get 3
    i64.store offset=56
    local.get 4
    i32.const 0
    i32.store offset=52
    local.get 4
    local.get 4
    i64.load offset=56
    i64.store offset=40
    local.get 4
    i32.const 0
    i32.store offset=32
    local.get 4
    i64.const 32
    i64.store offset=24
    local.get 4
    i32.const 0
    i32.store offset=16
    local.get 4
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=64
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=64
        local.get 4
        i64.load offset=40
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=40
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      local.get 4
      local.get 4
      i64.load offset=24
      local.get 3
      i64.add
      i64.store offset=24
      local.get 4
      local.get 4
      i64.load offset=24
      call $sgx_ocalloc
      i32.store offset=16
      block  ;; label = @2
        local.get 4
        i32.load offset=16
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 4
        i32.const 1
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 4
      local.get 4
      i32.load offset=16
      i32.store offset=32
      local.get 4
      local.get 4
      i32.load offset=16
      i64.extend_i32_u
      i64.const 32
      i64.add
      i32.wrap_i64
      i32.store offset=16
      local.get 4
      local.get 4
      i64.load offset=24
      i64.const 32
      i64.sub
      i64.store offset=24
      local.get 4
      i32.load offset=32
      local.get 4
      i32.load offset=68
      i32.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=32
          local.get 4
          i32.load offset=16
          i32.store offset=12
          local.get 4
          local.get 4
          i32.load offset=16
          i32.store offset=8
          local.get 4
          i32.load offset=8
          i32.const 0
          local.get 4
          i64.load offset=40
          i32.wrap_i64
          call $memset
          drop
          local.get 4
          local.get 4
          i32.load offset=16
          i64.extend_i32_u
          local.get 4
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 4
          local.get 4
          i64.load offset=24
          local.get 4
          i64.load offset=40
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 4
        i32.load offset=32
        i32.const 0
        i32.store offset=12
      end
      local.get 4
      i32.load offset=32
      local.get 4
      i64.load offset=56
      i64.store offset=16
      local.get 4
      i32.const 2
      local.get 4
      i32.load offset=32
      call $sgx_ocall
      i32.store offset=52
      block  ;; label = @2
        local.get 4
        i32.load offset=52
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 4
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=72
          local.get 4
          i32.load offset=32
          i64.load
          i64.store
        end
        block  ;; label = @3
          local.get 4
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 4
            i32.load offset=64
            local.get 4
            i64.load offset=40
            local.get 4
            i32.load offset=8
            local.get 4
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 1
            i32.store offset=76
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 4
      local.get 4
      i32.load offset=52
      i32.store offset=76
    end
    local.get 4
    i32.load offset=76
    local.set 2
    local.get 4
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $ocall_write (type 11) (param i32 i32 i32 i64) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=56
    local.get 4
    local.get 1
    i32.store offset=52
    local.get 4
    local.get 2
    i32.store offset=48
    local.get 4
    local.get 3
    i64.store offset=40
    local.get 4
    i32.const 0
    i32.store offset=36
    local.get 4
    local.get 4
    i64.load offset=40
    i64.store offset=24
    local.get 4
    i32.const 0
    i32.store offset=16
    local.get 4
    i64.const 32
    i64.store offset=8
    local.get 4
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=48
        local.get 4
        i64.load offset=24
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=24
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      local.get 4
      local.get 4
      i64.load offset=8
      local.get 3
      i64.add
      i64.store offset=8
      local.get 4
      local.get 4
      i64.load offset=8
      call $sgx_ocalloc
      i32.store
      block  ;; label = @2
        local.get 4
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 4
        i32.const 1
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 4
      local.get 4
      i32.load
      i32.store offset=16
      local.get 4
      local.get 4
      i32.load
      i64.extend_i32_u
      i64.const 32
      i64.add
      i32.wrap_i64
      i32.store
      local.get 4
      local.get 4
      i64.load offset=8
      i64.const 32
      i64.sub
      i64.store offset=8
      local.get 4
      i32.load offset=16
      local.get 4
      i32.load offset=52
      i32.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=16
          local.get 4
          i32.load
          i32.store offset=12
          block  ;; label = @4
            local.get 4
            i32.load
            local.get 4
            i64.load offset=8
            local.get 4
            i32.load offset=48
            local.get 4
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 4
          local.get 4
          i32.load
          i64.extend_i32_u
          local.get 4
          i64.load offset=24
          i64.add
          i32.wrap_i64
          i32.store
          local.get 4
          local.get 4
          i64.load offset=8
          local.get 4
          i64.load offset=24
          i64.sub
          i64.store offset=8
          br 1 (;@2;)
        end
        local.get 4
        i32.load offset=16
        i32.const 0
        i32.store offset=12
      end
      local.get 4
      i32.load offset=16
      local.get 4
      i64.load offset=40
      i64.store offset=16
      local.get 4
      i32.const 3
      local.get 4
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=36
      block  ;; label = @2
        local.get 4
        i32.load offset=36
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 4
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=56
          local.get 4
          i32.load offset=16
          i64.load
          i64.store
        end
      end
      call $sgx_ocfree
      local.get 4
      local.get 4
      i32.load offset=36
      i32.store offset=60
    end
    local.get 4
    i32.load offset=60
    local.set 2
    local.get 4
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $ocall_close (type 6) (param i32 i32) (result i32)
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
    i32.store offset=36
    local.get 2
    i32.const 0
    i32.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 8
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
      i64.const 8
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 2
      local.get 2
      i64.load offset=16
      i64.const 8
      i64.sub
      i64.store offset=16
      local.get 2
      i32.load offset=24
      local.get 2
      i32.load offset=36
      i32.store offset=4
      local.get 2
      i32.const 4
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=32
      block  ;; label = @2
        local.get 2
        i32.load offset=32
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
      i32.load offset=32
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
  (func $ocall_print (type 10) (param i32) (result i32)
    (local i32 i64)
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
      i64.store offset=8
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
      i32.const 5
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
  (func $sgx_oc_cpuidex (type 7) (param i32 i32 i32) (result i32)
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
      i64.store offset=16
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
      i32.const 6
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
  (func $sgx_thread_wait_untrusted_event_ocall (type 6) (param i32 i32) (result i32)
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
      i32.const 7
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
  (func $sgx_thread_set_untrusted_event_ocall (type 6) (param i32 i32) (result i32)
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
  (func $sgx_thread_setwait_untrusted_events_ocall (type 7) (param i32 i32 i32) (result i32)
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
      i32.const 9
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
  (func $sgx_thread_set_multiple_untrusted_events_ocall (type 12) (param i32 i32 i64) (result i32)
    (local i32)
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
      i64.store offset=8
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
      i32.const 10
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
  (func $u_sgxprotectedfs_exclusive_file_open (type 13) (param i32 i32 i32 i32 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 112
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    local.get 0
    i32.store offset=104
    local.get 5
    local.get 1
    i32.store offset=96
    local.get 5
    local.get 2
    i32.store8 offset=95
    local.get 5
    local.get 3
    i32.store offset=88
    local.get 5
    local.get 4
    i32.store offset=80
    local.get 5
    i32.const 0
    i32.store offset=76
    block  ;; label = @1
      block  ;; label = @2
        local.get 5
        i32.load offset=96
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=96
        call $strlen
        i64.const 1
        i64.add
        local.set 6
        br 1 (;@1;)
      end
      i64.const 0
      local.set 6
    end
    local.get 5
    local.get 6
    i64.store offset=64
    local.get 5
    i64.const 8
    i64.store offset=56
    local.get 5
    i64.const 4
    i64.store offset=48
    local.get 5
    i32.const 0
    i32.store offset=40
    local.get 5
    i64.const 40
    i64.store offset=32
    local.get 5
    i32.const 0
    i32.store offset=24
    local.get 5
    i32.const 0
    i32.store offset=16
    local.get 5
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 5
        i32.load offset=96
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=96
        local.get 5
        i64.load offset=64
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 5
        i32.const 2
        i32.store offset=108
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 5
        i32.load offset=88
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=88
        local.get 5
        i64.load offset=56
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 5
        i32.const 2
        i32.store offset=108
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 5
        i32.load offset=80
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=80
        local.get 5
        i64.load offset=48
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 5
        i32.const 2
        i32.store offset=108
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=96
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i64.load offset=64
          local.set 6
          br 1 (;@2;)
        end
        i64.const 0
        local.set 6
      end
      local.get 5
      local.get 5
      i64.load offset=32
      local.get 6
      i64.add
      i64.store offset=32
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i64.load offset=56
          local.set 6
          br 1 (;@2;)
        end
        i64.const 0
        local.set 6
      end
      local.get 5
      local.get 5
      i64.load offset=32
      local.get 6
      i64.add
      i64.store offset=32
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i64.load offset=48
          local.set 6
          br 1 (;@2;)
        end
        i64.const 0
        local.set 6
      end
      local.get 5
      local.get 5
      i64.load offset=32
      local.get 6
      i64.add
      i64.store offset=32
      local.get 5
      local.get 5
      i64.load offset=32
      call $sgx_ocalloc
      i32.store offset=24
      block  ;; label = @2
        local.get 5
        i32.load offset=24
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 5
        i32.const 1
        i32.store offset=108
        br 1 (;@1;)
      end
      local.get 5
      local.get 5
      i32.load offset=24
      i32.store offset=40
      local.get 5
      local.get 5
      i32.load offset=24
      i64.extend_i32_u
      i64.const 40
      i64.add
      i32.wrap_i64
      i32.store offset=24
      local.get 5
      local.get 5
      i64.load offset=32
      i64.const 40
      i64.sub
      i64.store offset=32
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=96
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=40
          local.get 5
          i32.load offset=24
          i32.store offset=4
          block  ;; label = @4
            local.get 5
            i32.load offset=24
            local.get 5
            i64.load offset=32
            local.get 5
            i32.load offset=96
            local.get 5
            i64.load offset=64
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 5
            i32.const 1
            i32.store offset=108
            br 3 (;@1;)
          end
          local.get 5
          local.get 5
          i32.load offset=24
          i64.extend_i32_u
          local.get 5
          i64.load offset=64
          i64.add
          i32.wrap_i64
          i32.store offset=24
          local.get 5
          local.get 5
          i64.load offset=32
          local.get 5
          i64.load offset=64
          i64.sub
          i64.store offset=32
          br 1 (;@2;)
        end
        local.get 5
        i32.load offset=40
        i32.const 0
        i32.store offset=4
      end
      local.get 5
      i32.load offset=40
      local.get 5
      i32.load8_u offset=95
      i32.store8 offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=40
          local.get 5
          i32.load offset=24
          i32.store offset=12
          local.get 5
          local.get 5
          i32.load offset=24
          i32.store offset=16
          local.get 5
          i32.load offset=16
          i32.const 0
          local.get 5
          i64.load offset=56
          i32.wrap_i64
          call $memset
          drop
          local.get 5
          local.get 5
          i32.load offset=24
          i64.extend_i32_u
          local.get 5
          i64.load offset=56
          i64.add
          i32.wrap_i64
          i32.store offset=24
          local.get 5
          local.get 5
          i64.load offset=32
          local.get 5
          i64.load offset=56
          i64.sub
          i64.store offset=32
          br 1 (;@2;)
        end
        local.get 5
        i32.load offset=40
        i32.const 0
        i32.store offset=12
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=40
          local.get 5
          i32.load offset=24
          i32.store offset=16
          local.get 5
          local.get 5
          i32.load offset=24
          i32.store offset=8
          local.get 5
          i32.load offset=8
          i32.const 0
          local.get 5
          i64.load offset=48
          i32.wrap_i64
          call $memset
          drop
          local.get 5
          local.get 5
          i32.load offset=24
          i64.extend_i32_u
          local.get 5
          i64.load offset=48
          i64.add
          i32.wrap_i64
          i32.store offset=24
          local.get 5
          local.get 5
          i64.load offset=32
          local.get 5
          i64.load offset=48
          i64.sub
          i64.store offset=32
          br 1 (;@2;)
        end
        local.get 5
        i32.load offset=40
        i32.const 0
        i32.store offset=16
      end
      local.get 5
      i32.const 11
      local.get 5
      i32.load offset=40
      call $sgx_ocall
      i32.store offset=76
      block  ;; label = @2
        local.get 5
        i32.load offset=76
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 5
          i32.load offset=104
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=104
          local.get 5
          i32.load offset=40
          i32.load
          i32.store
        end
        block  ;; label = @3
          local.get 5
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 5
            i32.load offset=88
            local.get 5
            i64.load offset=56
            local.get 5
            i32.load offset=16
            local.get 5
            i64.load offset=56
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 5
            i32.const 1
            i32.store offset=108
            br 3 (;@1;)
          end
        end
        block  ;; label = @3
          local.get 5
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 5
            i32.load offset=80
            local.get 5
            i64.load offset=48
            local.get 5
            i32.load offset=8
            local.get 5
            i64.load offset=48
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 5
            i32.const 1
            i32.store offset=108
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 5
      local.get 5
      i32.load offset=76
      i32.store offset=108
    end
    local.get 5
    i32.load offset=108
    local.set 4
    local.get 5
    i32.const 112
    i32.add
    global.set $__stack_pointer
    local.get 4)
  (func $u_sgxprotectedfs_check_if_file_exists (type 6) (param i32 i32) (result i32)
    (local i32 i64)
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
    i32.store offset=48
    local.get 2
    i32.const 0
    i32.store offset=44
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        call $strlen
        i64.const 1
        i64.add
        local.set 3
        br 1 (;@1;)
      end
      i64.const 0
      local.set 3
    end
    local.get 2
    local.get 3
    i64.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 16
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        local.get 2
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 2
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i64.load offset=32
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      local.get 2
      local.get 2
      i64.load offset=16
      local.get 3
      i64.add
      i64.store offset=16
      local.get 2
      local.get 2
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
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
        i32.store offset=60
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
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=24
          local.get 2
          i32.load offset=8
          i32.store offset=4
          block  ;; label = @4
            local.get 2
            i32.load offset=8
            local.get 2
            i64.load offset=16
            local.get 2
            i32.load offset=48
            local.get 2
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 2
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 2
          local.get 2
          i32.load offset=8
          i64.extend_i32_u
          local.get 2
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 2
          local.get 2
          i64.load offset=16
          local.get 2
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 2
        i32.load offset=24
        i32.const 0
        i32.store offset=4
      end
      local.get 2
      i32.const 12
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=44
      block  ;; label = @2
        local.get 2
        i32.load offset=44
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=56
          local.get 2
          i32.load offset=24
          i32.load8_u
          i32.store8
        end
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=44
      i32.store offset=60
    end
    local.get 2
    i32.load offset=60
    local.set 1
    local.get 2
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $u_sgxprotectedfs_fread_node (type 14) (param i32 i32 i64 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 80
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
    i64.store offset=56
    local.get 5
    local.get 3
    i32.store offset=48
    local.get 5
    local.get 4
    i32.store offset=44
    local.get 5
    i32.const 0
    i32.store offset=40
    local.get 5
    local.get 5
    i32.load offset=44
    i64.extend_i32_u
    i64.store offset=32
    local.get 5
    i32.const 0
    i32.store offset=24
    local.get 5
    i64.const 40
    i64.store offset=16
    local.get 5
    i32.const 0
    i32.store offset=8
    local.get 5
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 5
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=48
        local.get 5
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 5
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i64.load offset=32
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 5
      local.get 5
      i64.load offset=16
      local.get 2
      i64.add
      i64.store offset=16
      local.get 5
      local.get 5
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
      block  ;; label = @2
        local.get 5
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 5
        i32.const 1
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 5
      local.get 5
      i32.load offset=8
      i32.store offset=24
      local.get 5
      local.get 5
      i32.load offset=8
      i64.extend_i32_u
      i64.const 40
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 5
      local.get 5
      i64.load offset=16
      i64.const 40
      i64.sub
      i64.store offset=16
      local.get 5
      i32.load offset=24
      local.get 5
      i32.load offset=64
      i32.store offset=4
      local.get 5
      i32.load offset=24
      local.get 5
      i64.load offset=56
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=24
          local.get 5
          i32.load offset=8
          i32.store offset=16
          local.get 5
          local.get 5
          i32.load offset=8
          i32.store
          local.get 5
          i32.load
          i32.const 0
          local.get 5
          i64.load offset=32
          i32.wrap_i64
          call $memset
          drop
          local.get 5
          local.get 5
          i32.load offset=8
          i64.extend_i32_u
          local.get 5
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 5
          local.get 5
          i64.load offset=16
          local.get 5
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 5
        i32.load offset=24
        i32.const 0
        i32.store offset=16
      end
      local.get 5
      i32.load offset=24
      local.get 5
      i32.load offset=44
      i32.store offset=20
      local.get 5
      i32.const 13
      local.get 5
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=40
      block  ;; label = @2
        local.get 5
        i32.load offset=40
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 5
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=72
          local.get 5
          i32.load offset=24
          i32.load
          i32.store
        end
        block  ;; label = @3
          local.get 5
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 5
            i32.load offset=48
            local.get 5
            i64.load offset=32
            local.get 5
            i32.load
            local.get 5
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 5
            i32.const 1
            i32.store offset=76
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 5
      local.get 5
      i32.load offset=40
      i32.store offset=76
    end
    local.get 5
    i32.load offset=76
    local.set 4
    local.get 5
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 4)
  (func $u_sgxprotectedfs_fwrite_node (type 14) (param i32 i32 i64 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 80
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
    i64.store offset=56
    local.get 5
    local.get 3
    i32.store offset=48
    local.get 5
    local.get 4
    i32.store offset=44
    local.get 5
    i32.const 0
    i32.store offset=40
    local.get 5
    local.get 5
    i32.load offset=44
    i64.extend_i32_u
    i64.store offset=32
    local.get 5
    i32.const 0
    i32.store offset=24
    local.get 5
    i64.const 40
    i64.store offset=16
    local.get 5
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 5
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=48
        local.get 5
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 5
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i64.load offset=32
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 5
      local.get 5
      i64.load offset=16
      local.get 2
      i64.add
      i64.store offset=16
      local.get 5
      local.get 5
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
      block  ;; label = @2
        local.get 5
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 5
        i32.const 1
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 5
      local.get 5
      i32.load offset=8
      i32.store offset=24
      local.get 5
      local.get 5
      i32.load offset=8
      i64.extend_i32_u
      i64.const 40
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 5
      local.get 5
      i64.load offset=16
      i64.const 40
      i64.sub
      i64.store offset=16
      local.get 5
      i32.load offset=24
      local.get 5
      i32.load offset=64
      i32.store offset=4
      local.get 5
      i32.load offset=24
      local.get 5
      i64.load offset=56
      i64.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=24
          local.get 5
          i32.load offset=8
          i32.store offset=16
          block  ;; label = @4
            local.get 5
            i32.load offset=8
            local.get 5
            i64.load offset=16
            local.get 5
            i32.load offset=48
            local.get 5
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 5
            i32.const 1
            i32.store offset=76
            br 3 (;@1;)
          end
          local.get 5
          local.get 5
          i32.load offset=8
          i64.extend_i32_u
          local.get 5
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 5
          local.get 5
          i64.load offset=16
          local.get 5
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 5
        i32.load offset=24
        i32.const 0
        i32.store offset=16
      end
      local.get 5
      i32.load offset=24
      local.get 5
      i32.load offset=44
      i32.store offset=20
      local.get 5
      i32.const 14
      local.get 5
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=40
      block  ;; label = @2
        local.get 5
        i32.load offset=40
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 5
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=72
          local.get 5
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 5
      local.get 5
      i32.load offset=40
      i32.store offset=76
    end
    local.get 5
    i32.load offset=76
    local.set 4
    local.get 5
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 4)
  (func $u_sgxprotectedfs_fclose (type 6) (param i32 i32) (result i32)
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
      i32.const 15
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
  (func $u_sgxprotectedfs_fflush (type 6) (param i32 i32) (result i32)
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
      i32.const 16
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
          i32.load8_u
          i32.store8
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
  (func $u_sgxprotectedfs_remove (type 6) (param i32 i32) (result i32)
    (local i32 i64)
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
    i32.store offset=48
    local.get 2
    i32.const 0
    i32.store offset=44
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        call $strlen
        i64.const 1
        i64.add
        local.set 3
        br 1 (;@1;)
      end
      i64.const 0
      local.set 3
    end
    local.get 2
    local.get 3
    i64.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 16
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        local.get 2
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 2
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i64.load offset=32
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      local.get 2
      local.get 2
      i64.load offset=16
      local.get 3
      i64.add
      i64.store offset=16
      local.get 2
      local.get 2
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
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
        i32.store offset=60
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
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=24
          local.get 2
          i32.load offset=8
          i32.store offset=4
          block  ;; label = @4
            local.get 2
            i32.load offset=8
            local.get 2
            i64.load offset=16
            local.get 2
            i32.load offset=48
            local.get 2
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 2
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 2
          local.get 2
          i32.load offset=8
          i64.extend_i32_u
          local.get 2
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 2
          local.get 2
          i64.load offset=16
          local.get 2
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 2
        i32.load offset=24
        i32.const 0
        i32.store offset=4
      end
      local.get 2
      i32.const 17
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=44
      block  ;; label = @2
        local.get 2
        i32.load offset=44
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=56
          local.get 2
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=44
      i32.store offset=60
    end
    local.get 2
    i32.load offset=60
    local.set 1
    local.get 2
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $u_sgxprotectedfs_recovery_file_open (type 6) (param i32 i32) (result i32)
    (local i32 i64)
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
    i32.store offset=48
    local.get 2
    i32.const 0
    i32.store offset=44
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        call $strlen
        i64.const 1
        i64.add
        local.set 3
        br 1 (;@1;)
      end
      i64.const 0
      local.set 3
    end
    local.get 2
    local.get 3
    i64.store offset=32
    local.get 2
    i32.const 0
    i32.store offset=24
    local.get 2
    i64.const 16
    i64.store offset=16
    local.get 2
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=48
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=48
        local.get 2
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 2
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i64.load offset=32
          local.set 3
          br 1 (;@2;)
        end
        i64.const 0
        local.set 3
      end
      local.get 2
      local.get 2
      i64.load offset=16
      local.get 3
      i64.add
      i64.store offset=16
      local.get 2
      local.get 2
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
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
        i32.store offset=60
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
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=24
          local.get 2
          i32.load offset=8
          i32.store offset=4
          block  ;; label = @4
            local.get 2
            i32.load offset=8
            local.get 2
            i64.load offset=16
            local.get 2
            i32.load offset=48
            local.get 2
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 2
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 2
          local.get 2
          i32.load offset=8
          i64.extend_i32_u
          local.get 2
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 2
          local.get 2
          i64.load offset=16
          local.get 2
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 2
        i32.load offset=24
        i32.const 0
        i32.store offset=4
      end
      local.get 2
      i32.const 18
      local.get 2
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=44
      block  ;; label = @2
        local.get 2
        i32.load offset=44
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=56
          local.get 2
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 2
      local.get 2
      i32.load offset=44
      i32.store offset=60
    end
    local.get 2
    i32.load offset=60
    local.set 1
    local.get 2
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $u_sgxprotectedfs_fwrite_recovery_node (type 15) (param i32 i32 i32 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=56
    local.get 4
    local.get 1
    i32.store offset=48
    local.get 4
    local.get 2
    i32.store offset=40
    local.get 4
    local.get 3
    i32.store offset=36
    local.get 4
    i32.const 0
    i32.store offset=32
    local.get 4
    local.get 4
    i32.load offset=36
    i64.extend_i32_u
    i64.const 0
    i64.shl
    i64.store offset=24
    local.get 4
    i32.const 0
    i32.store offset=16
    local.get 4
    i64.const 32
    i64.store offset=8
    local.get 4
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=40
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=40
        local.get 4
        i64.load offset=24
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=24
          local.set 5
          br 1 (;@2;)
        end
        i64.const 0
        local.set 5
      end
      local.get 4
      local.get 4
      i64.load offset=8
      local.get 5
      i64.add
      i64.store offset=8
      local.get 4
      local.get 4
      i64.load offset=8
      call $sgx_ocalloc
      i32.store
      block  ;; label = @2
        local.get 4
        i32.load
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 4
        i32.const 1
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 4
      local.get 4
      i32.load
      i32.store offset=16
      local.get 4
      local.get 4
      i32.load
      i64.extend_i32_u
      i64.const 32
      i64.add
      i32.wrap_i64
      i32.store
      local.get 4
      local.get 4
      i64.load offset=8
      i64.const 32
      i64.sub
      i64.store offset=8
      local.get 4
      i32.load offset=16
      local.get 4
      i32.load offset=48
      i32.store offset=4
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=40
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=16
          local.get 4
          i32.load
          i32.store offset=8
          block  ;; label = @4
            local.get 4
            i32.load
            local.get 4
            i64.load offset=8
            local.get 4
            i32.load offset=40
            local.get 4
            i64.load offset=24
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 1
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 4
          local.get 4
          i32.load
          i64.extend_i32_u
          local.get 4
          i64.load offset=24
          i64.add
          i32.wrap_i64
          i32.store
          local.get 4
          local.get 4
          i64.load offset=8
          local.get 4
          i64.load offset=24
          i64.sub
          i64.store offset=8
          br 1 (;@2;)
        end
        local.get 4
        i32.load offset=16
        i32.const 0
        i32.store offset=8
      end
      local.get 4
      i32.load offset=16
      local.get 4
      i32.load offset=36
      i32.store offset=12
      local.get 4
      i32.const 19
      local.get 4
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=32
      block  ;; label = @2
        local.get 4
        i32.load offset=32
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 4
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=56
          local.get 4
          i32.load offset=16
          i32.load8_u
          i32.store8
        end
      end
      call $sgx_ocfree
      local.get 4
      local.get 4
      i32.load offset=32
      i32.store offset=60
    end
    local.get 4
    i32.load offset=60
    local.set 3
    local.get 4
    i32.const 64
    i32.add
    global.set $__stack_pointer
    local.get 3)
  (func $u_sgxprotectedfs_do_file_recovery (type 15) (param i32 i32 i32 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=72
    local.get 4
    local.get 1
    i32.store offset=64
    local.get 4
    local.get 2
    i32.store offset=56
    local.get 4
    local.get 3
    i32.store offset=52
    local.get 4
    i32.const 0
    i32.store offset=48
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=64
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=64
        call $strlen
        i64.const 1
        i64.add
        local.set 5
        br 1 (;@1;)
      end
      i64.const 0
      local.set 5
    end
    local.get 4
    local.get 5
    i64.store offset=40
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=56
        call $strlen
        i64.const 1
        i64.add
        local.set 5
        br 1 (;@1;)
      end
      i64.const 0
      local.set 5
    end
    local.get 4
    local.get 5
    i64.store offset=32
    local.get 4
    i32.const 0
    i32.store offset=24
    local.get 4
    i64.const 32
    i64.store offset=16
    local.get 4
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=64
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=64
        local.get 4
        i64.load offset=40
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 4
        i32.load offset=56
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=56
        local.get 4
        i64.load offset=32
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=40
          local.set 5
          br 1 (;@2;)
        end
        i64.const 0
        local.set 5
      end
      local.get 4
      local.get 4
      i64.load offset=16
      local.get 5
      i64.add
      i64.store offset=16
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=32
          local.set 5
          br 1 (;@2;)
        end
        i64.const 0
        local.set 5
      end
      local.get 4
      local.get 4
      i64.load offset=16
      local.get 5
      i64.add
      i64.store offset=16
      local.get 4
      local.get 4
      i64.load offset=16
      call $sgx_ocalloc
      i32.store offset=8
      block  ;; label = @2
        local.get 4
        i32.load offset=8
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 4
        i32.const 1
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 4
      local.get 4
      i32.load offset=8
      i32.store offset=24
      local.get 4
      local.get 4
      i32.load offset=8
      i64.extend_i32_u
      i64.const 32
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 4
      local.get 4
      i64.load offset=16
      i64.const 32
      i64.sub
      i64.store offset=16
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=24
          local.get 4
          i32.load offset=8
          i32.store offset=4
          block  ;; label = @4
            local.get 4
            i32.load offset=8
            local.get 4
            i64.load offset=16
            local.get 4
            i32.load offset=64
            local.get 4
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 1
            i32.store offset=76
            br 3 (;@1;)
          end
          local.get 4
          local.get 4
          i32.load offset=8
          i64.extend_i32_u
          local.get 4
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 4
          local.get 4
          i64.load offset=16
          local.get 4
          i64.load offset=40
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 4
        i32.load offset=24
        i32.const 0
        i32.store offset=4
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=56
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=24
          local.get 4
          i32.load offset=8
          i32.store offset=8
          block  ;; label = @4
            local.get 4
            i32.load offset=8
            local.get 4
            i64.load offset=16
            local.get 4
            i32.load offset=56
            local.get 4
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 1
            i32.store offset=76
            br 3 (;@1;)
          end
          local.get 4
          local.get 4
          i32.load offset=8
          i64.extend_i32_u
          local.get 4
          i64.load offset=32
          i64.add
          i32.wrap_i64
          i32.store offset=8
          local.get 4
          local.get 4
          i64.load offset=16
          local.get 4
          i64.load offset=32
          i64.sub
          i64.store offset=16
          br 1 (;@2;)
        end
        local.get 4
        i32.load offset=24
        i32.const 0
        i32.store offset=8
      end
      local.get 4
      i32.load offset=24
      local.get 4
      i32.load offset=52
      i32.store offset=12
      local.get 4
      i32.const 20
      local.get 4
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=48
      block  ;; label = @2
        local.get 4
        i32.load offset=48
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 4
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=72
          local.get 4
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 4
      local.get 4
      i32.load offset=48
      i32.store offset=76
    end
    local.get 4
    i32.load offset=76
    local.set 3
    local.get 4
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 3)
  (func $create_session_ocall (type 13) (param i32 i32 i32 i32 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    local.get 0
    i32.store offset=88
    local.get 5
    local.get 1
    i32.store offset=80
    local.get 5
    local.get 2
    i32.store offset=72
    local.get 5
    local.get 3
    i32.store offset=68
    local.get 5
    local.get 4
    i32.store offset=64
    local.get 5
    i32.const 0
    i32.store offset=60
    local.get 5
    i64.const 4
    i64.store offset=48
    local.get 5
    local.get 5
    i32.load offset=68
    i64.extend_i32_u
    i64.store offset=40
    local.get 5
    i32.const 0
    i32.store offset=32
    local.get 5
    i64.const 32
    i64.store offset=24
    local.get 5
    i32.const 0
    i32.store offset=16
    local.get 5
    i32.const 0
    i32.store offset=8
    local.get 5
    i32.const 0
    i32.store
    block  ;; label = @1
      block  ;; label = @2
        local.get 5
        i32.load offset=80
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=80
        local.get 5
        i64.load offset=48
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 5
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 5
        i32.load offset=72
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.load offset=72
        local.get 5
        i64.load offset=40
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 5
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i64.load offset=48
          local.set 6
          br 1 (;@2;)
        end
        i64.const 0
        local.set 6
      end
      local.get 5
      local.get 5
      i64.load offset=24
      local.get 6
      i64.add
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i64.load offset=40
          local.set 6
          br 1 (;@2;)
        end
        i64.const 0
        local.set 6
      end
      local.get 5
      local.get 5
      i64.load offset=24
      local.get 6
      i64.add
      i64.store offset=24
      local.get 5
      local.get 5
      i64.load offset=24
      call $sgx_ocalloc
      i32.store offset=16
      block  ;; label = @2
        local.get 5
        i32.load offset=16
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 5
        i32.const 1
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 5
      local.get 5
      i32.load offset=16
      i32.store offset=32
      local.get 5
      local.get 5
      i32.load offset=16
      i64.extend_i32_u
      i64.const 32
      i64.add
      i32.wrap_i64
      i32.store offset=16
      local.get 5
      local.get 5
      i64.load offset=24
      i64.const 32
      i64.sub
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=32
          local.get 5
          i32.load offset=16
          i32.store offset=4
          local.get 5
          local.get 5
          i32.load offset=16
          i32.store offset=8
          local.get 5
          i32.load offset=8
          i32.const 0
          local.get 5
          i64.load offset=48
          i32.wrap_i64
          call $memset
          drop
          local.get 5
          local.get 5
          i32.load offset=16
          i64.extend_i32_u
          local.get 5
          i64.load offset=48
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 5
          local.get 5
          i64.load offset=24
          local.get 5
          i64.load offset=48
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 5
        i32.load offset=32
        i32.const 0
        i32.store offset=4
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 5
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=32
          local.get 5
          i32.load offset=16
          i32.store offset=8
          local.get 5
          local.get 5
          i32.load offset=16
          i32.store
          local.get 5
          i32.load
          i32.const 0
          local.get 5
          i64.load offset=40
          i32.wrap_i64
          call $memset
          drop
          local.get 5
          local.get 5
          i32.load offset=16
          i64.extend_i32_u
          local.get 5
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 5
          local.get 5
          i64.load offset=24
          local.get 5
          i64.load offset=40
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 5
        i32.load offset=32
        i32.const 0
        i32.store offset=8
      end
      local.get 5
      i32.load offset=32
      local.get 5
      i32.load offset=68
      i32.store offset=12
      local.get 5
      i32.load offset=32
      local.get 5
      i32.load offset=64
      i32.store offset=16
      local.get 5
      i32.const 21
      local.get 5
      i32.load offset=32
      call $sgx_ocall
      i32.store offset=60
      block  ;; label = @2
        local.get 5
        i32.load offset=60
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 5
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=88
          local.get 5
          i32.load offset=32
          i32.load
          i32.store
        end
        block  ;; label = @3
          local.get 5
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 5
            i32.load offset=80
            local.get 5
            i64.load offset=48
            local.get 5
            i32.load offset=8
            local.get 5
            i64.load offset=48
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 5
            i32.const 1
            i32.store offset=92
            br 3 (;@1;)
          end
        end
        block  ;; label = @3
          local.get 5
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 5
            i32.load offset=72
            local.get 5
            i64.load offset=40
            local.get 5
            i32.load
            local.get 5
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 5
            i32.const 1
            i32.store offset=92
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 5
      local.get 5
      i32.load offset=60
      i32.store offset=92
    end
    local.get 5
    i32.load offset=92
    local.set 4
    local.get 5
    i32.const 96
    i32.add
    global.set $__stack_pointer
    local.get 4)
  (func $exchange_report_ocall (type 16) (param i32 i32 i32 i32 i32 i32 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 7
    global.set $__stack_pointer
    local.get 7
    local.get 0
    i32.store offset=88
    local.get 7
    local.get 1
    i32.store offset=84
    local.get 7
    local.get 2
    i32.store offset=80
    local.get 7
    local.get 3
    i32.store offset=76
    local.get 7
    local.get 4
    i32.store offset=72
    local.get 7
    local.get 5
    i32.store offset=68
    local.get 7
    local.get 6
    i32.store offset=64
    local.get 7
    i32.const 0
    i32.store offset=60
    local.get 7
    local.get 7
    i32.load offset=76
    i64.extend_i32_u
    i64.store offset=48
    local.get 7
    local.get 7
    i32.load offset=68
    i64.extend_i32_u
    i64.store offset=40
    local.get 7
    i32.const 0
    i32.store offset=32
    local.get 7
    i64.const 40
    i64.store offset=24
    local.get 7
    i32.const 0
    i32.store offset=16
    local.get 7
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 7
        i32.load offset=80
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        i32.load offset=80
        local.get 7
        i64.load offset=48
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 7
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 7
        i32.load offset=72
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        i32.load offset=72
        local.get 7
        i64.load offset=40
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 7
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 7
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i64.load offset=48
          local.set 8
          br 1 (;@2;)
        end
        i64.const 0
        local.set 8
      end
      local.get 7
      local.get 7
      i64.load offset=24
      local.get 8
      i64.add
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 7
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i64.load offset=40
          local.set 8
          br 1 (;@2;)
        end
        i64.const 0
        local.set 8
      end
      local.get 7
      local.get 7
      i64.load offset=24
      local.get 8
      i64.add
      i64.store offset=24
      local.get 7
      local.get 7
      i64.load offset=24
      call $sgx_ocalloc
      i32.store offset=16
      block  ;; label = @2
        local.get 7
        i32.load offset=16
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 7
        i32.const 1
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 7
      local.get 7
      i32.load offset=16
      i32.store offset=32
      local.get 7
      local.get 7
      i32.load offset=16
      i64.extend_i32_u
      i64.const 40
      i64.add
      i32.wrap_i64
      i32.store offset=16
      local.get 7
      local.get 7
      i64.load offset=24
      i64.const 40
      i64.sub
      i64.store offset=24
      local.get 7
      i32.load offset=32
      local.get 7
      i32.load offset=84
      i32.store offset=4
      block  ;; label = @2
        block  ;; label = @3
          local.get 7
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=32
          local.get 7
          i32.load offset=16
          i32.store offset=8
          block  ;; label = @4
            local.get 7
            i32.load offset=16
            local.get 7
            i64.load offset=24
            local.get 7
            i32.load offset=80
            local.get 7
            i64.load offset=48
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 7
            i32.const 1
            i32.store offset=92
            br 3 (;@1;)
          end
          local.get 7
          local.get 7
          i32.load offset=16
          i64.extend_i32_u
          local.get 7
          i64.load offset=48
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 7
          local.get 7
          i64.load offset=24
          local.get 7
          i64.load offset=48
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 7
        i32.load offset=32
        i32.const 0
        i32.store offset=8
      end
      local.get 7
      i32.load offset=32
      local.get 7
      i32.load offset=76
      i32.store offset=12
      block  ;; label = @2
        block  ;; label = @3
          local.get 7
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=32
          local.get 7
          i32.load offset=16
          i32.store offset=16
          local.get 7
          local.get 7
          i32.load offset=16
          i32.store offset=8
          local.get 7
          i32.load offset=8
          i32.const 0
          local.get 7
          i64.load offset=40
          i32.wrap_i64
          call $memset
          drop
          local.get 7
          local.get 7
          i32.load offset=16
          i64.extend_i32_u
          local.get 7
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 7
          local.get 7
          i64.load offset=24
          local.get 7
          i64.load offset=40
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 7
        i32.load offset=32
        i32.const 0
        i32.store offset=16
      end
      local.get 7
      i32.load offset=32
      local.get 7
      i32.load offset=68
      i32.store offset=20
      local.get 7
      i32.load offset=32
      local.get 7
      i32.load offset=64
      i32.store offset=24
      local.get 7
      i32.const 22
      local.get 7
      i32.load offset=32
      call $sgx_ocall
      i32.store offset=60
      block  ;; label = @2
        local.get 7
        i32.load offset=60
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 7
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=88
          local.get 7
          i32.load offset=32
          i32.load
          i32.store
        end
        block  ;; label = @3
          local.get 7
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 7
            i32.load offset=72
            local.get 7
            i64.load offset=40
            local.get 7
            i32.load offset=8
            local.get 7
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 7
            i32.const 1
            i32.store offset=92
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 7
      local.get 7
      i32.load offset=60
      i32.store offset=92
    end
    local.get 7
    i32.load offset=92
    local.set 6
    local.get 7
    i32.const 96
    i32.add
    global.set $__stack_pointer
    local.get 6)
  (func $close_session_ocall (type 7) (param i32 i32 i32) (result i32)
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
    i32.store offset=36
    local.get 3
    local.get 2
    i32.store offset=32
    local.get 3
    i32.const 0
    i32.store offset=28
    local.get 3
    i32.const 0
    i32.store offset=24
    local.get 3
    i64.const 12
    i64.store offset=16
    local.get 3
    i32.const 0
    i32.store offset=8
    local.get 3
    local.get 3
    i64.load offset=16
    call $sgx_ocalloc
    i32.store offset=8
    block  ;; label = @1
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
        i32.store offset=44
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
      i64.const 12
      i64.add
      i32.wrap_i64
      i32.store offset=8
      local.get 3
      local.get 3
      i64.load offset=16
      i64.const 12
      i64.sub
      i64.store offset=16
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=36
      i32.store offset=4
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=32
      i32.store offset=8
      local.get 3
      i32.const 23
      local.get 3
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=28
      block  ;; label = @2
        local.get 3
        i32.load offset=28
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
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 3
      local.get 3
      i32.load offset=28
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
  (func $invoke_service_ocall (type 17) (param i32 i32 i32 i32 i32 i32) (result i32)
    (local i32 i64)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 6
    global.set $__stack_pointer
    local.get 6
    local.get 0
    i32.store offset=88
    local.get 6
    local.get 1
    i32.store offset=80
    local.get 6
    local.get 2
    i32.store offset=76
    local.get 6
    local.get 3
    i32.store offset=72
    local.get 6
    local.get 4
    i32.store offset=68
    local.get 6
    local.get 5
    i32.store offset=64
    local.get 6
    i32.const 0
    i32.store offset=60
    local.get 6
    local.get 6
    i32.load offset=76
    i64.extend_i32_u
    i64.store offset=48
    local.get 6
    local.get 6
    i32.load offset=68
    i64.extend_i32_u
    i64.store offset=40
    local.get 6
    i32.const 0
    i32.store offset=32
    local.get 6
    i64.const 40
    i64.store offset=24
    local.get 6
    i32.const 0
    i32.store offset=16
    local.get 6
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 6
        i32.load offset=80
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        i32.load offset=80
        local.get 6
        i64.load offset=48
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 6
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 6
        i32.load offset=72
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        i32.load offset=72
        local.get 6
        i64.load offset=40
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 6
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 6
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 6
          i64.load offset=48
          local.set 7
          br 1 (;@2;)
        end
        i64.const 0
        local.set 7
      end
      local.get 6
      local.get 6
      i64.load offset=24
      local.get 7
      i64.add
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 6
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 6
          i64.load offset=40
          local.set 7
          br 1 (;@2;)
        end
        i64.const 0
        local.set 7
      end
      local.get 6
      local.get 6
      i64.load offset=24
      local.get 7
      i64.add
      i64.store offset=24
      local.get 6
      local.get 6
      i64.load offset=24
      call $sgx_ocalloc
      i32.store offset=16
      block  ;; label = @2
        local.get 6
        i32.load offset=16
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 6
        i32.const 1
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 6
      local.get 6
      i32.load offset=16
      i32.store offset=32
      local.get 6
      local.get 6
      i32.load offset=16
      i64.extend_i32_u
      i64.const 40
      i64.add
      i32.wrap_i64
      i32.store offset=16
      local.get 6
      local.get 6
      i64.load offset=24
      i64.const 40
      i64.sub
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 6
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=32
          local.get 6
          i32.load offset=16
          i32.store offset=4
          block  ;; label = @4
            local.get 6
            i32.load offset=16
            local.get 6
            i64.load offset=24
            local.get 6
            i32.load offset=80
            local.get 6
            i64.load offset=48
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 6
            i32.const 1
            i32.store offset=92
            br 3 (;@1;)
          end
          local.get 6
          local.get 6
          i32.load offset=16
          i64.extend_i32_u
          local.get 6
          i64.load offset=48
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 6
          local.get 6
          i64.load offset=24
          local.get 6
          i64.load offset=48
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 6
        i32.load offset=32
        i32.const 0
        i32.store offset=4
      end
      local.get 6
      i32.load offset=32
      local.get 6
      i32.load offset=76
      i32.store offset=8
      block  ;; label = @2
        block  ;; label = @3
          local.get 6
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=32
          local.get 6
          i32.load offset=16
          i32.store offset=12
          local.get 6
          local.get 6
          i32.load offset=16
          i32.store offset=8
          local.get 6
          i32.load offset=8
          i32.const 0
          local.get 6
          i64.load offset=40
          i32.wrap_i64
          call $memset
          drop
          local.get 6
          local.get 6
          i32.load offset=16
          i64.extend_i32_u
          local.get 6
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 6
          local.get 6
          i64.load offset=24
          local.get 6
          i64.load offset=40
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 6
        i32.load offset=32
        i32.const 0
        i32.store offset=12
      end
      local.get 6
      i32.load offset=32
      local.get 6
      i32.load offset=68
      i32.store offset=16
      local.get 6
      i32.load offset=32
      local.get 6
      i32.load offset=64
      i32.store offset=20
      local.get 6
      i32.const 24
      local.get 6
      i32.load offset=32
      call $sgx_ocall
      i32.store offset=60
      block  ;; label = @2
        local.get 6
        i32.load offset=60
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 6
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=88
          local.get 6
          i32.load offset=32
          i32.load
          i32.store
        end
        block  ;; label = @3
          local.get 6
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 6
            i32.load offset=72
            local.get 6
            i64.load offset=40
            local.get 6
            i32.load offset=8
            local.get 6
            i64.load offset=40
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 6
            i32.const 1
            i32.store offset=92
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 6
      local.get 6
      i32.load offset=60
      i32.store offset=92
    end
    local.get 6
    i32.load offset=92
    local.set 5
    local.get 6
    i32.const 96
    i32.add
    global.set $__stack_pointer
    local.get 5)
  (func $printf_char_const*__..._ (type 6) (param i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 304
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=300
    local.get 2
    local.get 0
    i32.store offset=24
    local.get 2
    i32.const 32
    i32.add
    i32.const 0
    i32.const 256
    call $memset
    drop
    local.get 2
    local.get 1
    i32.store
    local.get 2
    i32.const 32
    i32.add
    i64.const 256
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
    call $ocall_print
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=300
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 304
    i32.add
    global.set $__stack_pointer
    i32.const 0)
  (func $open_char_const*_ (type 10) (param i32) (result i32)
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
    local.get 1
    i32.const 4
    i32.add
    local.get 1
    i32.load offset=8
    call $ocall_open
    drop
    local.get 1
    i32.load offset=4
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $create_char_const*_ (type 10) (param i32) (result i32)
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
    local.get 1
    i32.const 4
    i32.add
    local.get 1
    i32.load offset=8
    call $ocall_create
    drop
    local.get 1
    i32.load offset=4
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (func $read_int__void*__unsigned_long_ (type 18) (param i32 i32 i64) (result i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=28
    local.get 3
    local.get 1
    i32.store offset=24
    local.get 3
    local.get 2
    i64.store offset=16
    local.get 3
    i64.const 0
    i64.store offset=8
    local.get 3
    i32.const 8
    i32.add
    local.get 3
    i32.load offset=28
    local.get 3
    i32.load offset=24
    local.get 3
    i64.load offset=16
    call $ocall_read
    drop
    local.get 3
    i64.load offset=8
    local.set 2
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $write_int__void_const*__unsigned_long_ (type 18) (param i32 i32 i64) (result i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=28
    local.get 3
    local.get 1
    i32.store offset=24
    local.get 3
    local.get 2
    i64.store offset=16
    local.get 3
    i64.const 0
    i64.store offset=8
    local.get 3
    i32.const 8
    i32.add
    local.get 3
    i32.load offset=28
    local.get 3
    i32.load offset=24
    local.get 3
    i64.load offset=16
    call $ocall_write
    drop
    local.get 3
    i64.load offset=8
    local.set 2
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $close_int_ (type 10) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=12
    local.get 1
    i32.const 0
    i32.store offset=8
    local.get 1
    i32.const 8
    i32.add
    local.get 1
    i32.load offset=12
    call $ocall_close
    drop
    local.get 1
    i32.load offset=8
    local.set 0
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 0)
  (table (;0;) 3 3 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66656))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1048))
  (global (;3;) i32 (i32.const 1024))
  (global (;4;) i32 (i32.const 1116))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 66656))
  (global (;7;) i32 (i32.const 0))
  (global (;8;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "ecall_encrypt_file" (func $ecall_encrypt_file))
  (export "ecall_decrypt_file" (func $ecall_decrypt_file))
  (export "ocall_open" (func $ocall_open))
  (export "ocall_create" (func $ocall_create))
  (export "ocall_read" (func $ocall_read))
  (export "ocall_write" (func $ocall_write))
  (export "ocall_close" (func $ocall_close))
  (export "ocall_print" (func $ocall_print))
  (export "sgx_oc_cpuidex" (func $sgx_oc_cpuidex))
  (export "sgx_thread_wait_untrusted_event_ocall" (func $sgx_thread_wait_untrusted_event_ocall))
  (export "sgx_thread_set_untrusted_event_ocall" (func $sgx_thread_set_untrusted_event_ocall))
  (export "sgx_thread_setwait_untrusted_events_ocall" (func $sgx_thread_setwait_untrusted_events_ocall))
  (export "sgx_thread_set_multiple_untrusted_events_ocall" (func $sgx_thread_set_multiple_untrusted_events_ocall))
  (export "u_sgxprotectedfs_exclusive_file_open" (func $u_sgxprotectedfs_exclusive_file_open))
  (export "u_sgxprotectedfs_check_if_file_exists" (func $u_sgxprotectedfs_check_if_file_exists))
  (export "u_sgxprotectedfs_fread_node" (func $u_sgxprotectedfs_fread_node))
  (export "u_sgxprotectedfs_fwrite_node" (func $u_sgxprotectedfs_fwrite_node))
  (export "u_sgxprotectedfs_fclose" (func $u_sgxprotectedfs_fclose))
  (export "u_sgxprotectedfs_fflush" (func $u_sgxprotectedfs_fflush))
  (export "u_sgxprotectedfs_remove" (func $u_sgxprotectedfs_remove))
  (export "u_sgxprotectedfs_recovery_file_open" (func $u_sgxprotectedfs_recovery_file_open))
  (export "u_sgxprotectedfs_fwrite_recovery_node" (func $u_sgxprotectedfs_fwrite_recovery_node))
  (export "u_sgxprotectedfs_do_file_recovery" (func $u_sgxprotectedfs_do_file_recovery))
  (export "create_session_ocall" (func $create_session_ocall))
  (export "exchange_report_ocall" (func $exchange_report_ocall))
  (export "close_session_ocall" (func $close_session_ocall))
  (export "invoke_service_ocall" (func $invoke_service_ocall))
  (export "_Z6printfPKcz" (func $printf_char_const*__..._))
  (export "_Z4openPKc" (func $open_char_const*_))
  (export "_Z6createPKc" (func $create_char_const*_))
  (export "_Z4readiPvm" (func $read_int__void*__unsigned_long_))
  (export "_Z5writeiPKvm" (func $write_int__void_const*__unsigned_long_))
  (export "_Z5closei" (func $close_int_))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 3))
  (export "__data_end" (global 4))
  (export "__global_base" (global 5))
  (export "__heap_base" (global 6))
  (export "__memory_base" (global 7))
  (export "__table_base" (global 8))
  (elem (;0;) (i32.const 1) func $sgx_ecall_encrypt_file $sgx_ecall_decrypt_file)
  (data $.rodata (i32.const 1024) "\02\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\19\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00w\00r\00"))
