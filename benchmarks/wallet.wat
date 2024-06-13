(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32) (result i64)))
  (type (;4;) (func (param i32)))
  (type (;5;) (func (param i32 i32 i32) (result i32)))
  (type (;6;) (func))
  (type (;7;) (func (param i32 i32) (result i32)))
  (type (;8;) (func (param i32 i32 i64) (result i32)))
  (type (;9;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;10;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;11;) (func (param i32) (result i32)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "malloc" (func $malloc (type 1)))
  (import "env" "memcpy_s" (func $memcpy_s (type 2)))
  (import "env" "strlen" (func $strlen (type 3)))
  (import "env" "free" (func $free (type 4)))
  (import "env" "memset" (func $memset (type 5)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 1)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 6)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 7)))
  (import "env" "strncpy" (func $strncpy (type 8)))
  (import "env" "strcmp" (func $strcmp (type 7)))
  (import "env" "memcpy" (func $memcpy (type 5)))
  (import "env" "sgx_seal_data" (func $sgx_seal_data (type 9)))
  (import "env" "sgx_unseal_data" (func $sgx_unseal_data (type 10)))
  (func $__wasm_call_ctors (type 6))
  (func $sgx_ecall_create_wallet (type 11) (param i32) (result i32)
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
          i64.const 24
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
      i32.load offset=4
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
        call $ecall_create_wallet
        local.set 0
        local.get 1
        i32.load offset=32
        local.get 0
        i32.store
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
  (func $ecall_create_wallet (type 11) (param i32) (result i32)
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
          call $strlen
          i64.const 8
          i64.lt_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=40
          call $strlen
          i64.const 1
          i64.add
          i64.const 100
          i64.gt_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 1
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.const 28
      i32.add
      call $ocall_is_wallet
      i32.store offset=36
      block  ;; label = @2
        local.get 1
        i32.load offset=28
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      i64.const 30112
      call $malloc
      i32.store offset=24
      local.get 1
      i32.load offset=24
      i64.const 0
      i64.store offset=30000
      local.get 1
      i32.load offset=24
      i32.const 30008
      i32.add
      local.get 1
      i32.load offset=40
      local.get 1
      i32.load offset=40
      call $strlen
      i64.const 1
      i64.add
      call $strncpy
      drop
      local.get 1
      i64.const 30672
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      call $malloc
      i32.store offset=8
      local.get 1
      local.get 1
      i32.load offset=24
      local.get 1
      i32.load offset=8
      local.get 1
      i64.load offset=16
      call $seal_wallet_Wallet_const*___sealed_data_t*__unsigned_long_
      i32.store offset=32
      local.get 1
      i32.load offset=24
      call $free
      block  ;; label = @2
        local.get 1
        i32.load offset=32
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.load offset=8
        call $free
        local.get 1
        i32.const 9
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.const 28
      i32.add
      local.get 1
      i32.load offset=8
      local.get 1
      i64.load offset=16
      call $ocall_save_wallet
      i32.store offset=36
      local.get 1
      i32.load offset=8
      call $free
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.load offset=28
          br_if 0 (;@3;)
          local.get 1
          i32.load offset=36
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 3
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 1
      i32.const 0
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
  (func $sgx_ecall_show_wallet (type 11) (param i32) (result i32)
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
          i64.const 40
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
      local.get 1
      i64.load offset=24
      i64.store offset=16
      local.get 1
      i32.const 0
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
        i64.load offset=16
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
            i32.store offset=60
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
        i32.load offset=40
        local.get 1
        i32.load offset=8
        local.get 1
        i64.load offset=24
        call $ecall_show_wallet
        local.set 0
        local.get 1
        i32.load offset=64
        local.get 0
        i32.store
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
            i32.load offset=32
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
            i32.store offset=60
            br 2 (;@2;)
          end
        end
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
  (func $ecall_show_wallet (type 8) (param i32 i32 i64) (result i32)
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
    i64.const 30672
    i64.store offset=16
    local.get 3
    local.get 3
    i64.load offset=16
    call $malloc
    i32.store offset=8
    local.get 3
    local.get 3
    i32.const 28
    i32.add
    local.get 3
    i32.load offset=8
    local.get 3
    i64.load offset=16
    call $ocall_load_wallet
    i32.store offset=36
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=28
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=36
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 3
        i32.load offset=8
        call $free
        local.get 3
        i32.const 4
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      i32.const 30112
      i32.store offset=4
      local.get 3
      local.get 3
      i32.load offset=4
      i64.extend_i32_u
      call $malloc
      i32.store
      local.get 3
      local.get 3
      i32.load offset=8
      local.get 3
      i32.load
      local.get 3
      i32.load offset=4
      call $unseal_wallet__sealed_data_t_const*__Wallet*__unsigned_int_
      i32.store offset=32
      local.get 3
      i32.load offset=8
      call $free
      block  ;; label = @2
        local.get 3
        i32.load offset=32
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load
        call $free
        local.get 3
        i32.const 10
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 3
        i32.load
        i32.const 30008
        i32.add
        local.get 3
        i32.load offset=56
        call $strcmp
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load
        call $free
        local.get 3
        i32.const 5
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=48
      local.get 3
      i32.load
      i32.const 30112
      call $memcpy
      drop
      local.get 3
      i32.load
      call $free
      local.get 3
      i32.const 0
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
  (func $sgx_ecall_change_master_password (type 11) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    local.get 0
    i32.store offset=56
    block  ;; label = @1
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
          i32.load offset=56
          i64.const 40
          call $sgx_is_outside_enclave
          br_if 1 (;@2;)
        end
        local.get 1
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 1
      local.get 1
      i32.load offset=56
      i32.store offset=48
      local.get 1
      i32.const 0
      i32.store offset=44
      local.get 1
      local.get 1
      i32.load offset=48
      i32.load offset=4
      i32.store offset=40
      local.get 1
      local.get 1
      i32.load offset=48
      i64.load offset=8
      i64.store offset=32
      local.get 1
      i32.const 0
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=48
      i32.load offset=16
      i32.store offset=16
      local.get 1
      local.get 1
      i32.load offset=48
      i64.load offset=24
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
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
        i64.load offset=32
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=60
        br 1 (;@1;)
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
        local.get 1
        i64.load offset=8
        call $sgx_is_outside_enclave
        br_if 0 (;@2;)
        local.get 1
        i32.const 2
        i32.store offset=60
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
          i64.load offset=32
          i64.const 0
          i64.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 1
          i64.load offset=32
          call $malloc
          i32.store offset=24
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            i32.const 0
            i32.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 3
            i32.store offset=44
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=24
            local.get 1
            i64.load offset=32
            local.get 1
            i32.load offset=40
            local.get 1
            i64.load offset=32
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=44
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=24
          local.get 1
          i64.load offset=32
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          block  ;; label = @4
            local.get 1
            i64.load offset=32
            local.get 1
            i32.load offset=24
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
            i32.store offset=44
            br 2 (;@2;)
          end
        end
        block  ;; label = @3
          local.get 1
          i32.load offset=16
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
            i32.store offset=44
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load offset=16
            local.get 1
            i64.load offset=8
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            local.get 1
            i32.const 1
            i32.store offset=44
            br 2 (;@2;)
          end
          local.get 1
          i32.load
          local.get 1
          i64.load offset=8
          i64.const 1
          i64.sub
          i32.wrap_i64
          i32.add
          i32.const 0
          i32.store8
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            local.get 1
            i32.load
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
            i32.store offset=44
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=24
        local.get 1
        i32.load
        call $ecall_change_master_password
        local.set 0
        local.get 1
        i32.load offset=48
        local.get 0
        i32.store
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
      i32.load offset=44
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
  (func $ecall_change_master_password (type 7) (param i32 i32) (result i32)
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
    i32.store offset=48
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=48
          call $strlen
          i64.const 8
          i64.lt_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=48
          call $strlen
          i64.const 1
          i64.add
          i64.const 100
          i64.gt_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 2
        i32.const 1
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      i64.const 30672
      i64.store offset=24
      local.get 2
      local.get 2
      i64.load offset=24
      call $malloc
      i32.store offset=16
      local.get 2
      local.get 2
      i32.const 36
      i32.add
      local.get 2
      i32.load offset=16
      local.get 2
      i64.load offset=24
      call $ocall_load_wallet
      i32.store offset=44
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=36
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=44
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 2
        i32.load offset=16
        call $free
        local.get 2
        i32.const 4
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      i32.const 30112
      i32.store offset=12
      local.get 2
      local.get 2
      i32.load offset=12
      i64.extend_i32_u
      call $malloc
      i32.store offset=8
      local.get 2
      local.get 2
      i32.load offset=16
      local.get 2
      i32.load offset=8
      local.get 2
      i32.load offset=12
      call $unseal_wallet__sealed_data_t_const*__Wallet*__unsigned_int_
      i32.store offset=40
      local.get 2
      i32.load offset=16
      call $free
      block  ;; label = @2
        local.get 2
        i32.load offset=40
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=8
        call $free
        local.get 2
        i32.const 10
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        i32.load offset=8
        i32.const 30008
        i32.add
        local.get 2
        i32.load offset=56
        call $strcmp
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=8
        call $free
        local.get 2
        i32.const 5
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      i32.load offset=8
      i32.const 30008
      i32.add
      local.get 2
      i32.load offset=48
      local.get 2
      i32.load offset=48
      call $strlen
      i64.const 1
      i64.add
      call $strncpy
      drop
      local.get 2
      local.get 2
      i64.load offset=24
      call $malloc
      i32.store offset=16
      local.get 2
      local.get 2
      i32.load offset=8
      local.get 2
      i32.load offset=16
      local.get 2
      i64.load offset=24
      call $seal_wallet_Wallet_const*___sealed_data_t*__unsigned_long_
      i32.store offset=40
      local.get 2
      i32.load offset=8
      call $free
      block  ;; label = @2
        local.get 2
        i32.load offset=40
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=16
        call $free
        local.get 2
        i32.const 9
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.const 36
      i32.add
      local.get 2
      i32.load offset=16
      local.get 2
      i64.load offset=24
      call $ocall_save_wallet
      i32.store offset=44
      local.get 2
      i32.load offset=16
      call $free
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=36
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=44
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 2
        i32.const 3
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      i32.const 0
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
  (func $sgx_ecall_add_item (type 11) (param i32) (result i32)
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
          i64.const 40
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
      local.get 1
      i64.load offset=24
      i64.store offset=16
      local.get 1
      i32.const 0
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
        i64.load offset=16
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
            i32.store offset=60
            br 2 (;@2;)
          end
          block  ;; label = @4
            local.get 1
            i32.load offset=8
            local.get 1
            i64.load offset=16
            local.get 1
            i32.load offset=32
            local.get 1
            i64.load offset=16
            call $memcpy_s
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
        i32.load offset=8
        local.get 1
        i64.load offset=24
        call $ecall_add_item
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
  (func $ecall_add_item (type 8) (param i32 i32 i64) (result i32)
    (local i32)
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
    i32.store offset=64
    local.get 3
    local.get 2
    i64.store offset=56
    local.get 3
    i64.const 30672
    i64.store offset=32
    local.get 3
    local.get 3
    i64.load offset=32
    call $malloc
    i32.store offset=24
    local.get 3
    local.get 3
    i32.const 44
    i32.add
    local.get 3
    i32.load offset=24
    local.get 3
    i64.load offset=32
    call $ocall_load_wallet
    i32.store offset=52
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=44
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=52
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 3
        i32.load offset=24
        call $free
        local.get 3
        i32.const 4
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 3
      i32.const 30112
      i32.store offset=20
      local.get 3
      local.get 3
      i32.load offset=20
      i64.extend_i32_u
      call $malloc
      i32.store offset=16
      local.get 3
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=16
      local.get 3
      i32.load offset=20
      call $unseal_wallet__sealed_data_t_const*__Wallet*__unsigned_int_
      i32.store offset=48
      local.get 3
      i32.load offset=24
      call $free
      block  ;; label = @2
        local.get 3
        i32.load offset=48
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=16
        call $free
        local.get 3
        i32.const 10
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 3
        i32.load offset=16
        i32.const 30008
        i32.add
        local.get 3
        i32.load offset=72
        call $strcmp
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=16
        call $free
        local.get 3
        i32.const 5
        i32.store offset=76
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=64
          call $strlen
          i64.const 1
          i64.add
          i64.const 100
          i64.gt_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=64
          i32.const 100
          i32.add
          call $strlen
          i64.const 1
          i64.add
          i64.const 100
          i64.gt_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=64
          i32.const 200
          i32.add
          call $strlen
          i64.const 1
          i64.add
          i64.const 100
          i64.gt_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 3
        i32.load offset=16
        call $free
        local.get 3
        i32.const 8
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load offset=16
      i64.load offset=30000
      i64.store offset=8
      block  ;; label = @2
        local.get 3
        i64.load offset=8
        i64.const 100
        i64.ge_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=16
        call $free
        local.get 3
        i32.const 6
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=16
      local.get 3
      i64.load offset=8
      i32.wrap_i64
      i32.const 300
      i32.mul
      i32.add
      local.get 3
      i32.load offset=64
      i32.const 300
      call $memcpy
      drop
      local.get 3
      i32.load offset=16
      local.tee 1
      local.get 1
      i64.load offset=30000
      i64.const 1
      i64.add
      i64.store offset=30000
      local.get 3
      local.get 3
      i64.load offset=32
      call $malloc
      i32.store offset=24
      local.get 3
      local.get 3
      i32.load offset=16
      local.get 3
      i32.load offset=24
      local.get 3
      i64.load offset=32
      call $seal_wallet_Wallet_const*___sealed_data_t*__unsigned_long_
      i32.store offset=48
      local.get 3
      i32.load offset=16
      call $free
      block  ;; label = @2
        local.get 3
        i32.load offset=48
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=16
        call $free
        local.get 3
        i32.load offset=24
        call $free
        local.get 3
        i32.const 9
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.const 44
      i32.add
      local.get 3
      i32.load offset=24
      local.get 3
      i64.load offset=32
      call $ocall_save_wallet
      i32.store offset=52
      local.get 3
      i32.load offset=24
      call $free
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=44
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=52
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 3
        i32.const 3
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 3
      i32.const 0
      i32.store offset=76
    end
    local.get 3
    i32.load offset=76
    local.set 1
    local.get 3
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_ecall_remove_item (type 11) (param i32) (result i32)
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
          i64.const 32
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
      i32.load offset=4
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
        local.get 1
        i32.load offset=32
        i32.load offset=16
        call $ecall_remove_item
        local.set 0
        local.get 1
        i32.load offset=32
        local.get 0
        i32.store
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
  (func $ecall_remove_item (type 7) (param i32 i32) (result i32)
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
    i32.store offset=52
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=52
          i32.const 0
          i32.lt_s
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=52
          i32.const 100
          i32.ge_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 2
        i32.const 7
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      i64.const 30672
      i64.store offset=32
      local.get 2
      local.get 2
      i64.load offset=32
      call $malloc
      i32.store offset=24
      local.get 2
      local.get 2
      i32.const 40
      i32.add
      local.get 2
      i32.load offset=24
      local.get 2
      i64.load offset=32
      call $ocall_load_wallet
      i32.store offset=48
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=40
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=48
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 2
        i32.load offset=24
        call $free
        local.get 2
        i32.const 4
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      i32.const 30112
      i32.store offset=20
      local.get 2
      local.get 2
      i32.load offset=20
      i64.extend_i32_u
      call $malloc
      i32.store offset=16
      local.get 2
      local.get 2
      i32.load offset=24
      local.get 2
      i32.load offset=16
      local.get 2
      i32.load offset=20
      call $unseal_wallet__sealed_data_t_const*__Wallet*__unsigned_int_
      i32.store offset=44
      local.get 2
      i32.load offset=24
      call $free
      block  ;; label = @2
        local.get 2
        i32.load offset=44
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=16
        call $free
        local.get 2
        i32.const 10
        i32.store offset=60
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        i32.load offset=16
        i32.const 30008
        i32.add
        local.get 2
        i32.load offset=56
        call $strcmp
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=16
        call $free
        local.get 2
        i32.const 5
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.load offset=16
      i64.load offset=30000
      i64.store offset=8
      block  ;; label = @2
        local.get 2
        i32.load offset=52
        i64.extend_i32_s
        local.get 2
        i64.load offset=8
        i64.ge_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=16
        call $free
        local.get 2
        i32.const 7
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.load offset=52
      i32.store offset=4
      block  ;; label = @2
        loop  ;; label = @3
          local.get 2
          i32.load offset=4
          i64.extend_i32_s
          local.get 2
          i64.load offset=8
          i64.const 1
          i64.sub
          i64.lt_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 2
          i32.load offset=16
          local.get 2
          i32.load offset=4
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 300
          i32.mul
          i32.add
          local.get 2
          i32.load offset=16
          local.get 2
          i32.load offset=4
          i32.const 1
          i32.add
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 300
          i32.mul
          i32.add
          i32.const 300
          call $memcpy
          drop
          local.get 2
          local.get 2
          i32.load offset=4
          i32.const 1
          i32.add
          i32.store offset=4
          br 0 (;@3;)
        end
      end
      local.get 2
      i32.load offset=16
      local.tee 1
      local.get 1
      i64.load offset=30000
      i64.const -1
      i64.add
      i64.store offset=30000
      local.get 2
      local.get 2
      i64.load offset=32
      call $malloc
      i32.store offset=24
      local.get 2
      local.get 2
      i32.load offset=16
      local.get 2
      i32.load offset=24
      local.get 2
      i64.load offset=32
      call $seal_wallet_Wallet_const*___sealed_data_t*__unsigned_long_
      i32.store offset=44
      local.get 2
      i32.load offset=16
      call $free
      block  ;; label = @2
        local.get 2
        i32.load offset=44
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=24
        call $free
        local.get 2
        i32.const 9
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      local.get 2
      i32.const 40
      i32.add
      local.get 2
      i32.load offset=24
      local.get 2
      i64.load offset=32
      call $ocall_save_wallet
      i32.store offset=48
      local.get 2
      i32.load offset=24
      call $free
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=40
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=48
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 2
        i32.const 3
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      i32.const 0
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
  (func $ocall_debug_print (type 11) (param i32) (result i32)
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
  (func $ocall_save_wallet (type 8) (param i32 i32 i64) (result i32)
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
      i32.const 1
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
  (func $ocall_load_wallet (type 8) (param i32 i32 i64) (result i32)
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
    i32.store offset=64
    local.get 3
    local.get 2
    i64.store offset=56
    local.get 3
    i32.const 0
    i32.store offset=52
    local.get 3
    local.get 3
    i64.load offset=56
    i64.store offset=40
    local.get 3
    i32.const 0
    i32.store offset=32
    local.get 3
    i64.const 24
    i64.store offset=24
    local.get 3
    i32.const 0
    i32.store offset=16
    local.get 3
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=64
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=64
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
        block  ;; label = @3
          local.get 3
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.load offset=40
          local.set 2
          br 1 (;@2;)
        end
        i64.const 0
        local.set 2
      end
      local.get 3
      local.get 3
      i64.load offset=24
      local.get 2
      i64.add
      local.tee 2
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=64
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
        local.get 2
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
      i64.load offset=24
      call $sgx_ocalloc
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
        call $sgx_ocfree
        local.get 3
        i32.const 1
        i32.store offset=76
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load offset=16
      i32.store offset=32
      local.get 3
      local.get 3
      i32.load offset=16
      i64.extend_i32_u
      i64.const 24
      i64.add
      i32.wrap_i64
      i32.store offset=16
      local.get 3
      local.get 3
      i64.load offset=24
      i64.const 24
      i64.sub
      i64.store offset=24
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=32
          local.get 3
          i32.load offset=16
          i32.store offset=4
          local.get 3
          local.get 3
          i32.load offset=16
          i32.store offset=8
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
          local.get 3
          i32.load offset=8
          i32.const 0
          local.get 3
          i64.load offset=40
          i32.wrap_i64
          call $memset
          drop
          local.get 3
          local.get 3
          i32.load offset=16
          i64.extend_i32_u
          local.get 3
          i64.load offset=40
          i64.add
          i32.wrap_i64
          i32.store offset=16
          local.get 3
          local.get 3
          i64.load offset=24
          local.get 3
          i64.load offset=40
          i64.sub
          i64.store offset=24
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=32
        i32.const 0
        i32.store offset=4
      end
      local.get 3
      i32.load offset=32
      local.get 3
      i64.load offset=56
      i64.store offset=8
      local.get 3
      i32.const 2
      local.get 3
      i32.load offset=32
      call $sgx_ocall
      i32.store offset=52
      block  ;; label = @2
        local.get 3
        i32.load offset=52
        br_if 0 (;@2;)
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
          i32.load offset=72
          local.get 3
          i32.load offset=32
          i32.load
          i32.store
        end
        block  ;; label = @3
          local.get 3
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 3
            i32.load offset=64
            local.get 3
            i64.load offset=40
            local.get 3
            i32.load offset=8
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
        end
      end
      call $sgx_ocfree
      local.get 3
      local.get 3
      i32.load offset=52
      i32.store offset=76
    end
    local.get 3
    i32.load offset=76
    local.set 1
    local.get 3
    i32.const 80
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $ocall_is_wallet (type 11) (param i32) (result i32)
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
    i64.const 4
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
      i64.const 4
      i64.add
      i32.wrap_i64
      i32.store
      local.get 1
      local.get 1
      i64.load offset=8
      i64.const 4
      i64.sub
      i64.store offset=8
      local.get 1
      i32.const 3
      local.get 1
      i32.load offset=16
      call $sgx_ocall
      i32.store offset=20
      block  ;; label = @2
        local.get 1
        i32.load offset=20
        br_if 0 (;@2;)
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
          local.get 1
          i32.load offset=16
          i32.load
          i32.store
        end
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
  (func $seal_wallet_Wallet_const*___sealed_data_t*__unsigned_long_ (type 8) (param i32 i32 i64) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=24
    local.get 3
    local.get 1
    i32.store offset=16
    local.get 3
    local.get 2
    i64.store offset=8
    i32.const 0
    i32.const 0
    i32.const 30112
    local.get 3
    i32.load offset=24
    local.get 3
    i64.load offset=8
    i32.wrap_i64
    local.get 3
    i32.load offset=16
    call $sgx_seal_data
    local.set 1
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $unseal_wallet__sealed_data_t_const*__Wallet*__unsigned_int_ (type 5) (param i32 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=24
    local.get 3
    local.get 1
    i32.store offset=16
    local.get 3
    local.get 2
    i32.store offset=12
    local.get 3
    i32.load offset=24
    i32.const 0
    i32.const 0
    local.get 3
    i32.load offset=16
    local.get 3
    i32.const 12
    i32.add
    call $sgx_unseal_data
    local.set 2
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (table (;0;) 6 6 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66640))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1072))
  (global (;3;) i32 (i32.const 1024))
  (global (;4;) i32 (i32.const 1104))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 66640))
  (global (;7;) i32 (i32.const 0))
  (global (;8;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "ecall_create_wallet" (func $ecall_create_wallet))
  (export "ecall_show_wallet" (func $ecall_show_wallet))
  (export "ecall_change_master_password" (func $ecall_change_master_password))
  (export "ecall_add_item" (func $ecall_add_item))
  (export "ecall_remove_item" (func $ecall_remove_item))
  (export "ocall_debug_print" (func $ocall_debug_print))
  (export "ocall_save_wallet" (func $ocall_save_wallet))
  (export "ocall_load_wallet" (func $ocall_load_wallet))
  (export "ocall_is_wallet" (func $ocall_is_wallet))
  (export "_Z11seal_walletPK6WalletP14_sealed_data_tm" (func $seal_wallet_Wallet_const*___sealed_data_t*__unsigned_long_))
  (export "_Z13unseal_walletPK14_sealed_data_tP6Walletj" (func $unseal_wallet__sealed_data_t_const*__Wallet*__unsigned_int_))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 3))
  (export "__data_end" (global 4))
  (export "__global_base" (global 5))
  (export "__heap_base" (global 6))
  (export "__memory_base" (global 7))
  (export "__table_base" (global 8))
  (elem (;0;) (i32.const 1) func $sgx_ecall_create_wallet $sgx_ecall_show_wallet $sgx_ecall_change_master_password $sgx_ecall_add_item $sgx_ecall_remove_item)
  (data $.rodata (i32.const 1024) "\05\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\05\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"))
