(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32)))
  (type (;4;) (func (param i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32) (result i64)))
  (type (;6;) (func))
  (type (;7;) (func (param i32 i32) (result i32)))
  (type (;8;) (func (param i64 i64) (result i32)))
  (type (;9;) (func (param f64 f64) (result f64)))
  (type (;10;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;11;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;12;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;13;) (func (param i32) (result i32)))
  (type (;14;) (func (param i32 i32 i32 i64)))
  (type (;15;) (func (param i32 i32 i32 i32 f32 i32) (result i32)))
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
  (import "env" "calloc" (func $calloc (type 8)))
  (import "env" "pow" (func $pow (type 9)))
  (import "env" "snprintf" (func $snprintf (type 10)))
  (import "env" "sgx_seal_data" (func $sgx_seal_data (type 11)))
  (import "env" "sgx_unseal_data" (func $sgx_unseal_data (type 12)))
  (func $__wasm_call_ctors (type 6))
  (func $sgx_secure_kmeans (type 13) (param i32) (result i32)
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
      i32.load
      i32.store offset=24
      local.get 1
      local.get 1
      i32.load offset=32
      i64.load offset=16
      i64.store offset=16
      local.get 1
      local.get 1
      i64.load offset=16
      i64.const 3
      i64.shl
      i64.store offset=8
      local.get 1
      i32.const 0
      i32.store
      block  ;; label = @2
        local.get 1
        i64.load offset=16
        i64.const 2305843009213693951
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
            i64.const 7
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
        i32.load offset=32
        i32.load offset=4
        local.get 1
        i32.load offset=32
        i32.load offset=8
        local.get 1
        i64.load offset=16
        call $secure_kmeans
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
  (func $secure_kmeans (type 14) (param i32 i32 i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 272
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=264
    local.get 4
    local.get 1
    i32.store offset=260
    local.get 4
    local.get 2
    i32.store offset=256
    local.get 4
    local.get 3
    i64.store offset=248
    local.get 4
    i32.load offset=260
    local.set 2
    local.get 4
    local.get 4
    i32.load offset=256
    i32.store offset=20
    local.get 4
    local.get 2
    i32.store offset=16
    local.get 4
    i32.const 48
    i32.add
    i64.const 200
    i32.const 1103
    local.get 4
    i32.const 16
    i32.add
    call $snprintf
    drop
    local.get 4
    i32.const 48
    i32.add
    call $print_message
    drop
    i32.const 1159
    call $print_message
    drop
    i32.const 1150
    call $print_message
    drop
    local.get 4
    i32.const 2
    i32.store offset=36
    local.get 4
    local.get 4
    i32.load offset=264
    local.get 4
    i32.load offset=260
    local.get 4
    i32.load offset=36
    local.get 4
    i32.load offset=256
    f32.const 0x1.a36e2ep-14 (;=0.0001;)
    i32.const 0
    call $k_means_float**__int__int__int__float__float**_
    i32.store offset=40
    i32.const 1141
    call $print_message
    drop
    local.get 4
    i32.const 0
    i32.store offset=32
    block  ;; label = @1
      loop  ;; label = @2
        local.get 4
        i32.load offset=32
        i32.const 20
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.load offset=32
        local.set 2
        local.get 4
        local.get 4
        i32.load offset=40
        local.get 4
        i32.load offset=32
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        i32.load
        i32.store offset=4
        local.get 4
        local.get 2
        i32.store
        local.get 4
        i32.const 48
        i32.add
        i64.const 200
        i32.const 1072
        local.get 4
        call $snprintf
        drop
        local.get 4
        i32.const 48
        i32.add
        call $print_message
        drop
        local.get 4
        local.get 4
        i32.load offset=32
        i32.const 1
        i32.add
        i32.store offset=32
        br 0 (;@2;)
      end
    end
    local.get 4
    i32.load offset=40
    call $free
    i32.const 1132
    call $print_message
    drop
    local.get 4
    i32.const 272
    i32.add
    global.set $__stack_pointer)
  (func $sgx_seal (type 13) (param i32) (result i32)
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
        call $seal
        local.set 0
        local.get 1
        i32.load offset=64
        local.get 0
        i32.store
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
  (func $seal (type 2) (param i32 i64 i32 i64) (result i32)
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
    local.get 4
    i32.const 0
    i32.const 0
    local.get 4
    i64.load offset=32
    i32.wrap_i64
    local.get 4
    i32.load offset=40
    local.get 4
    i64.load offset=16
    i32.wrap_i64
    local.get 4
    i32.load offset=24
    call $sgx_seal_data
    i32.store offset=12
    local.get 4
    i32.load offset=12
    local.set 2
    local.get 4
    i32.const 48
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $sgx_unseal (type 13) (param i32) (result i32)
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
      i32.load offset=20
      i32.store offset=20
      local.get 1
      local.get 1
      i32.load offset=20
      i64.extend_i32_u
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
        i32.load offset=20
        call $unseal
        local.set 0
        local.get 1
        i32.load offset=64
        local.get 0
        i32.store
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
  (func $unseal (type 10) (param i32 i64 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=24
    local.get 4
    local.get 1
    i64.store offset=16
    local.get 4
    local.get 2
    i32.store offset=8
    local.get 4
    local.get 3
    i32.store offset=4
    local.get 4
    local.get 4
    i32.load offset=24
    i32.const 0
    i32.const 0
    local.get 4
    i32.load offset=8
    local.get 4
    i32.const 4
    i32.add
    call $sgx_unseal_data
    i32.store
    local.get 4
    i32.load
    local.set 3
    local.get 4
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 3)
  (func $print_message (type 13) (param i32) (result i32)
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
  (func $k_means_float**__int__int__int__float__float**_ (type 15) (param i32 i32 i32 i32 f32 i32) (result i32)
    (local i32)
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
    i32.store offset=84
    local.get 6
    local.get 2
    i32.store offset=80
    local.get 6
    local.get 3
    i32.store offset=76
    local.get 6
    local.get 4
    f32.store offset=72
    local.get 6
    local.get 5
    i32.store offset=64
    local.get 6
    local.get 6
    i32.load offset=84
    i64.extend_i32_s
    i64.const 4
    call $calloc
    i32.store offset=56
    local.get 6
    local.get 6
    i32.load offset=76
    i64.extend_i32_s
    i64.const 4
    call $calloc
    i32.store offset=40
    local.get 6
    f32.const inf (;=inf;)
    f32.store offset=32
    block  ;; label = @1
      block  ;; label = @2
        local.get 6
        i32.load offset=64
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        i32.load offset=64
        local.set 5
        br 1 (;@1;)
      end
      local.get 6
      i32.load offset=76
      local.get 6
      i32.load offset=80
      i32.mul
      i64.extend_i32_s
      i64.const 8
      call $calloc
      local.set 5
    end
    local.get 6
    local.get 5
    i32.store offset=24
    local.get 6
    local.get 6
    i32.load offset=76
    local.get 6
    i32.load offset=80
    i32.mul
    i64.extend_i32_s
    i64.const 8
    call $calloc
    i32.store offset=16
    local.get 6
    i32.const 0
    i32.store offset=48
    local.get 6
    i32.const 0
    i32.store offset=52
    block  ;; label = @1
      loop  ;; label = @2
        local.get 6
        i32.load offset=48
        local.get 6
        i32.load offset=76
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 6
        i32.load offset=80
        i64.extend_i32_s
        i64.const 4
        call $calloc
        local.set 5
        local.get 6
        i32.load offset=16
        local.get 6
        i32.load offset=48
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        local.get 5
        i32.store
        block  ;; label = @3
          local.get 6
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=80
          i64.extend_i32_s
          i64.const 4
          call $calloc
          local.set 5
          local.get 6
          i32.load offset=24
          local.get 6
          i32.load offset=48
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          local.get 5
          i32.store
        end
        local.get 6
        local.get 6
        i32.load offset=80
        i32.store offset=44
        block  ;; label = @3
          loop  ;; label = @4
            local.get 6
            local.get 6
            i32.load offset=44
            local.tee 5
            i32.const -1
            i32.add
            i32.store offset=44
            local.get 5
            i32.const 0
            i32.gt_s
            i32.const 1
            i32.and
            i32.eqz
            br_if 1 (;@3;)
            local.get 6
            i32.load offset=24
            local.get 6
            i32.load offset=48
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            i32.load
            local.get 6
            i32.load offset=44
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            local.get 6
            i32.load offset=88
            local.get 6
            i32.load offset=52
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            i32.load
            local.get 6
            i32.load offset=44
            i64.extend_i32_s
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            f32.load
            f32.store
            br 0 (;@4;)
          end
        end
        local.get 6
        local.get 6
        i32.load offset=52
        local.get 6
        i32.load offset=84
        local.get 6
        i32.load offset=76
        i32.div_s
        i32.add
        i32.store offset=52
        local.get 6
        local.get 6
        i32.load offset=48
        i32.const 1
        i32.add
        i32.store offset=48
        br 0 (;@2;)
      end
    end
    loop  ;; label = @1
      local.get 6
      local.get 6
      f32.load offset=32
      f32.store offset=36
      local.get 6
      i32.const 0
      f32.convert_i32_s
      f32.store offset=32
      local.get 6
      i32.const 0
      i32.store offset=48
      block  ;; label = @2
        loop  ;; label = @3
          local.get 6
          i32.load offset=48
          local.get 6
          i32.load offset=76
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 6
          i32.const 0
          i32.store offset=44
          block  ;; label = @4
            loop  ;; label = @5
              local.get 6
              i32.load offset=44
              local.get 6
              i32.load offset=80
              i32.lt_s
              i32.const 1
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              local.get 6
              i32.load offset=16
              local.get 6
              i32.load offset=48
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.load
              local.set 5
              local.get 6
              local.get 6
              i32.load offset=44
              local.tee 3
              i32.const 1
              i32.add
              i32.store offset=44
              local.get 5
              local.get 3
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.const 0
              f32.convert_i32_s
              f32.store
              br 0 (;@5;)
            end
          end
          local.get 6
          i32.load offset=40
          local.set 5
          local.get 6
          local.get 6
          i32.load offset=48
          local.tee 3
          i32.const 1
          i32.add
          i32.store offset=48
          local.get 5
          local.get 3
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.const 0
          i32.store
          br 0 (;@3;)
        end
      end
      local.get 6
      i32.const 0
      i32.store offset=52
      block  ;; label = @2
        loop  ;; label = @3
          local.get 6
          i32.load offset=52
          local.get 6
          i32.load offset=84
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 6
          f32.const inf (;=inf;)
          f32.store offset=12
          local.get 6
          i32.const 0
          i32.store offset=48
          block  ;; label = @4
            loop  ;; label = @5
              local.get 6
              i32.load offset=48
              local.get 6
              i32.load offset=76
              i32.lt_s
              i32.const 1
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              local.get 6
              i32.const 0
              f32.convert_i32_s
              f32.store offset=8
              local.get 6
              local.get 6
              i32.load offset=80
              i32.store offset=44
              block  ;; label = @6
                loop  ;; label = @7
                  local.get 6
                  local.get 6
                  i32.load offset=44
                  local.tee 5
                  i32.const -1
                  i32.add
                  i32.store offset=44
                  local.get 5
                  i32.const 0
                  i32.gt_s
                  i32.const 1
                  i32.and
                  i32.eqz
                  br_if 1 (;@6;)
                  local.get 6
                  local.get 6
                  i32.load offset=88
                  local.get 6
                  i32.load offset=52
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  local.get 6
                  i32.load offset=44
                  i32.const 2
                  i32.shl
                  local.tee 5
                  i32.add
                  f32.load
                  local.get 6
                  i32.load offset=24
                  local.get 6
                  i32.load offset=48
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  local.get 5
                  i32.add
                  f32.load
                  f32.sub
                  f64.promote_f32
                  f64.const 0x1p+1 (;=2;)
                  call $pow
                  local.get 6
                  f32.load offset=8
                  f64.promote_f32
                  f64.add
                  f32.demote_f64
                  f32.store offset=8
                  br 0 (;@7;)
                end
              end
              block  ;; label = @6
                local.get 6
                f32.load offset=8
                local.get 6
                f32.load offset=12
                f32.lt
                i32.const 1
                i32.and
                i32.eqz
                br_if 0 (;@6;)
                local.get 6
                i32.load offset=56
                local.get 6
                i32.load offset=52
                i64.extend_i32_s
                i32.wrap_i64
                i32.const 2
                i32.shl
                i32.add
                local.get 6
                i32.load offset=48
                i32.store
                local.get 6
                local.get 6
                f32.load offset=8
                f32.store offset=12
              end
              local.get 6
              local.get 6
              i32.load offset=48
              i32.const 1
              i32.add
              i32.store offset=48
              br 0 (;@5;)
            end
          end
          local.get 6
          local.get 6
          i32.load offset=80
          i32.store offset=44
          block  ;; label = @4
            loop  ;; label = @5
              local.get 6
              local.get 6
              i32.load offset=44
              local.tee 5
              i32.const -1
              i32.add
              i32.store offset=44
              local.get 5
              i32.const 0
              i32.gt_s
              i32.const 1
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              local.get 6
              i32.load offset=16
              local.get 6
              i32.load offset=56
              local.get 6
              i32.load offset=52
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.load
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.load
              local.get 6
              i32.load offset=44
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              local.tee 5
              local.get 5
              f32.load
              local.get 6
              i32.load offset=88
              local.get 6
              i32.load offset=52
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.load
              local.get 6
              i32.load offset=44
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              f32.load
              f32.add
              f32.store
              br 0 (;@5;)
            end
          end
          local.get 6
          i32.load offset=40
          local.get 6
          i32.load offset=56
          local.get 6
          i32.load offset=52
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          local.tee 5
          local.get 5
          i32.load
          i32.const 1
          i32.add
          i32.store
          local.get 6
          local.get 6
          f32.load offset=32
          local.get 6
          f32.load offset=12
          f32.add
          f32.store offset=32
          local.get 6
          local.get 6
          i32.load offset=52
          i32.const 1
          i32.add
          i32.store offset=52
          br 0 (;@3;)
        end
      end
      local.get 6
      i32.const 0
      i32.store offset=48
      block  ;; label = @2
        loop  ;; label = @3
          local.get 6
          i32.load offset=48
          local.get 6
          i32.load offset=76
          i32.lt_s
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
          local.get 6
          i32.const 0
          i32.store offset=44
          block  ;; label = @4
            loop  ;; label = @5
              local.get 6
              i32.load offset=44
              local.get 6
              i32.load offset=80
              i32.lt_s
              i32.const 1
              i32.and
              i32.eqz
              br_if 1 (;@4;)
              block  ;; label = @6
                block  ;; label = @7
                  local.get 6
                  i32.load offset=40
                  local.get 6
                  i32.load offset=48
                  i64.extend_i32_s
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  i32.eqz
                  br_if 0 (;@7;)
                  local.get 6
                  i32.load offset=16
                  local.get 6
                  i32.load offset=48
                  i64.extend_i32_s
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  local.get 6
                  i32.load offset=44
                  i64.extend_i32_s
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  f32.load
                  local.get 6
                  i32.load offset=40
                  local.get 6
                  i32.load offset=48
                  i64.extend_i32_s
                  i32.wrap_i64
                  i32.const 2
                  i32.shl
                  i32.add
                  i32.load
                  f32.convert_i32_s
                  f32.div
                  local.set 4
                  br 1 (;@6;)
                end
                local.get 6
                i32.load offset=16
                local.get 6
                i32.load offset=48
                i64.extend_i32_s
                i32.wrap_i64
                i32.const 2
                i32.shl
                i32.add
                i32.load
                local.get 6
                i32.load offset=44
                i64.extend_i32_s
                i32.wrap_i64
                i32.const 2
                i32.shl
                i32.add
                f32.load
                local.set 4
              end
              local.get 6
              i32.load offset=24
              local.get 6
              i32.load offset=48
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              i32.load
              local.get 6
              i32.load offset=44
              i64.extend_i32_s
              i32.wrap_i64
              i32.const 2
              i32.shl
              i32.add
              local.get 4
              f32.store
              local.get 6
              local.get 6
              i32.load offset=44
              i32.const 1
              i32.add
              i32.store offset=44
              br 0 (;@5;)
            end
          end
          local.get 6
          local.get 6
          i32.load offset=48
          i32.const 1
          i32.add
          i32.store offset=48
          br 0 (;@3;)
        end
      end
      local.get 6
      f32.load offset=32
      local.get 6
      f32.load offset=36
      f32.sub
      f64.promote_f32
      f64.abs
      local.get 6
      f32.load offset=72
      f64.promote_f32
      f64.gt
      i32.const 1
      i32.and
      br_if 0 (;@1;)
    end
    local.get 6
    i32.const 0
    i32.store offset=48
    block  ;; label = @1
      loop  ;; label = @2
        local.get 6
        i32.load offset=48
        local.get 6
        i32.load offset=76
        i32.lt_s
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          local.get 6
          i32.load offset=64
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=24
          local.get 6
          i32.load offset=48
          i64.extend_i32_s
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          call $free
        end
        local.get 6
        i32.load offset=16
        local.get 6
        i32.load offset=48
        i64.extend_i32_s
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        i32.load
        call $free
        local.get 6
        local.get 6
        i32.load offset=48
        i32.const 1
        i32.add
        i32.store offset=48
        br 0 (;@2;)
      end
    end
    block  ;; label = @1
      local.get 6
      i32.load offset=64
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      local.get 6
      i32.load offset=24
      call $free
    end
    local.get 6
    i32.load offset=16
    call $free
    local.get 6
    i32.load offset=40
    call $free
    local.get 6
    i32.load offset=56
    local.set 5
    local.get 6
    i32.const 96
    i32.add
    global.set $__stack_pointer
    local.get 5)
  (table (;0;) 4 4 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66704))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1056))
  (global (;3;) i32 (i32.const 1024))
  (global (;4;) i32 (i32.const 1168))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 66704))
  (global (;7;) i32 (i32.const 0))
  (global (;8;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "secure_kmeans" (func $secure_kmeans))
  (export "seal" (func $seal))
  (export "unseal" (func $unseal))
  (export "print_message" (func $print_message))
  (export "_Z7k_meansPPfiiifS0_" (func $k_means_float**__int__int__int__float__float**_))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 3))
  (export "__data_end" (global 4))
  (export "__global_base" (global 5))
  (export "__heap_base" (global 6))
  (export "__memory_base" (global 7))
  (export "__table_base" (global 8))
  (elem (;0;) (i32.const 1) func $sgx_secure_kmeans $sgx_seal $sgx_unseal)
  (data $.rodata (i32.const 1024) "\03\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00data point %d is in cluster %d\00data size: %d, # cluster: %d\00DEBUG_E3\00DEBUG_E2\00DEBUG_E1\00DEBUG_E0\00"))
