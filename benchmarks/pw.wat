(module
  (type (;0;) (func (param i32 i32)))
  (type (;1;) (func (param i32)))
  (type (;2;) (func (param i32 i32 i64)))
  (type (;3;) (func (param i32 i32) (result i32)))
  (type (;4;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32 i32 i32) (result i32)))
  (type (;6;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;7;) (func (param i32 i64) (result i32)))
  (type (;8;) (func (param i32 i32 i32 i32)))
  (type (;9;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;10;) (func))
  (type (;11;) (func (param i64) (result i32)))
  (type (;12;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;13;) (func (param i32) (result i64)))
  (type (;14;) (func (param i32 i64)))
  (type (;15;) (func (result i32)))
  (type (;16;) (func (param i32) (result i32)))
  (type (;17;) (func (param i32 i32 i32)))
  (type (;18;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;19;) (func (param i32 i64 i32 i64 i32 i32 i64 i32)))
  (type (;20;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;21;) (func (param i32 i32 i64) (result i32)))
  (type (;22;) (func (param i32 i32 i64 i32 i64 i32 i32)))
  (type (;23;) (func (param i32 i32 i64 i32 i64 i32 i32 i32)))
  (type (;24;) (func (param i32 i32 i64 i32 i32 i64 i32 i32)))
  (type (;25;) (func (param i32 i32 i32 i64)))
  (type (;26;) (func (param i32 i32 i64 i32 i32 i32 i64 i32 i32)))
  (type (;27;) (func (param i32 i32 i32 i64 i32 i32)))
  (type (;28;) (func (param i32 i32 i64 i32)))
  (type (;29;) (func (param i32 i64 i32 i64 i32 i32)))
  (type (;30;) (func (param i64 i32)))
  (import "env" "sgx_calc_sealed_data_size" (func $sgx_calc_sealed_data_size (type 3)))
  (import "env" "sgx_seal_data" (func $sgx_seal_data (type 4)))
  (import "env" "memset" (func $memset (type 5)))
  (import "env" "sgx_unseal_data" (func $sgx_unseal_data (type 6)))
  (import "env" "sgx_read_rand" (func $sgx_read_rand (type 7)))
  (import "env" "__assert" (func $__assert (type 8)))
  (import "env" "sgx_rijndael128GCM_encrypt" (func $sgx_rijndael128GCM_encrypt (type 9)))
  (import "env" "sgx_rijndael128GCM_decrypt" (func $sgx_rijndael128GCM_decrypt (type 9)))
  (import "env" "abort" (func $abort (type 10)))
  (import "env" "memcpy" (func $memcpy (type 5)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 7)))
  (import "env" "malloc" (func $malloc (type 11)))
  (import "env" "memcpy_s" (func $memcpy_s (type 12)))
  (import "env" "free" (func $free (type 1)))
  (import "env" "strlen" (func $strlen (type 13)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 7)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 11)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 10)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 3)))
  (func $__wasm_call_ctors (type 10))
  (func $pw_region_enroll (type 3) (param i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 1056
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=1048
    local.get 2
    local.get 1
    i32.store offset=1044
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=1044
        i32.const 16
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.const 1
        i32.store offset=1052
        br 1 (;@1;)
      end
      local.get 2
      i32.const 0
      local.get 2
      i32.load offset=1044
      call $sgx_calc_sealed_data_size
      i32.store offset=1040
      block  ;; label = @2
        i64.const 1024
        local.get 2
        i32.load offset=1040
        i64.extend_i32_s
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.const 4
        i32.store offset=1052
        br 1 (;@1;)
      end
      block  ;; label = @2
        i32.const 0
        i32.const 0
        local.get 2
        i32.load offset=1044
        local.get 2
        i32.load offset=1048
        local.get 2
        i32.load offset=1040
        local.get 2
        i32.const 16
        i32.add
        call $sgx_seal_data
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.const 4
        i32.store offset=1052
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        i32.const 12
        i32.add
        local.get 2
        i32.const 16
        i32.add
        local.get 2
        i32.load offset=1040
        call $write_region_data
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.const 4
        i32.store offset=1052
        br 1 (;@1;)
      end
      local.get 2
      i32.const 16
      i32.add
      i64.const 1024
      call $mem_clean
      local.get 2
      local.get 2
      i32.load offset=12
      i32.store offset=1052
    end
    local.get 2
    i32.load offset=1052
    local.set 1
    local.get 2
    i32.const 1056
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $write_region_data (type 5) (param i32 i32 i32) (result i32)
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
    i32.store offset=48
    local.get 3
    local.get 2
    i32.store offset=44
    local.get 3
    i32.const 0
    i32.store offset=40
    local.get 3
    local.get 3
    i32.load offset=44
    i64.extend_i32_u
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
          i32.load offset=48
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
          i32.load offset=48
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
          i32.load offset=48
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
          i32.store offset=4
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
            i32.store offset=60
            br 3 (;@1;)
          end
          block  ;; label = @4
            local.get 3
            i32.load offset=8
            local.get 3
            i64.load offset=16
            local.get 3
            i32.load offset=48
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
        i32.store offset=4
      end
      local.get 3
      i32.load offset=24
      local.get 3
      i32.load offset=44
      i32.store offset=8
      local.get 3
      i32.const 1
      local.get 3
      i32.load offset=24
      call $sgx_ocall
      i32.store offset=40
      block  ;; label = @2
        local.get 3
        i32.load offset=40
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
          i32.load offset=24
          i32.load
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 3
      local.get 3
      i32.load offset=40
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
  (func $mem_clean (type 14) (param i32 i64)
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
    block  ;; label = @1
      local.get 2
      i64.load
      i64.const 0
      i64.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      i32.load offset=8
      i32.const 0
      local.get 2
      i64.load
      i32.wrap_i64
      call $memset
      drop
      local.get 2
      i32.load offset=8
      i32.load8_u
      drop
    end
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $pw_setup (type 6) (param i32 i32 i32 i32 i32) (result i32)
    (local i32)
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
    i32.store offset=84
    local.get 5
    local.get 2
    i32.store offset=80
    local.get 5
    local.get 3
    i32.store offset=76
    local.get 5
    local.get 4
    i32.store offset=72
    local.get 5
    i32.const 16
    i32.add
    local.tee 4
    i64.const 0
    i64.store align=4
    local.get 4
    i32.const 48
    i32.add
    i64.const 0
    i64.store align=4
    local.get 4
    i32.const 40
    i32.add
    i64.const 0
    i64.store align=4
    local.get 4
    i32.const 32
    i32.add
    i64.const 0
    i64.store align=4
    local.get 4
    i32.const 24
    i32.add
    i64.const 0
    i64.store align=4
    local.get 4
    i32.const 16
    i32.add
    i64.const 0
    i64.store align=4
    local.get 4
    i32.const 8
    i32.add
    i64.const 0
    i64.store align=4
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=1488
        br_if 0 (;@2;)
        local.get 5
        call $fetch_region_key
        i32.store offset=12
        block  ;; label = @3
          local.get 5
          i32.load offset=12
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          local.get 5
          i32.load offset=12
          i32.store offset=92
          br 2 (;@1;)
        end
      end
      local.get 5
      local.get 5
      i32.const 16
      i32.add
      call $pwrecord_fresh
      i32.store offset=12
      block  ;; label = @2
        local.get 5
        i32.load offset=12
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        local.get 5
        i32.load offset=12
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 5
      i32.const 16
      i32.add
      local.get 5
      i32.load offset=88
      local.get 5
      i32.load offset=84
      call $pwrecord_init_hash
      local.get 5
      local.get 5
      i32.const 16
      i32.add
      local.get 5
      i32.load offset=80
      local.get 5
      i32.load offset=76
      local.get 5
      i32.load offset=72
      call $pwrecord_encrypt
      i32.store offset=12
      local.get 5
      i32.const 16
      i32.add
      call $pwrecord_clean
      local.get 5
      local.get 5
      i32.load offset=12
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
  (func $fetch_region_key (type 15) (result i32)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 1072
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.const 12
        i32.add
        local.get 0
        i32.const 32
        i32.add
        i32.const 1024
        local.get 0
        i32.const 8
        i32.add
        call $read_region_data
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i32.const 1
        i32.store offset=1068
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 0
        i32.load offset=12
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 0
        i32.load offset=12
        i32.store offset=1068
        br 1 (;@1;)
      end
      local.get 0
      i32.const 16
      i32.store offset=4
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.const 32
          i32.add
          i32.const 0
          i32.const 0
          local.get 0
          i32.const 16
          i32.add
          local.get 0
          i32.const 4
          i32.add
          call $sgx_unseal_data
          br_if 0 (;@3;)
          local.get 0
          i32.load offset=4
          i32.const 16
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 0
        i32.const 2
        i32.store offset=1068
        br 1 (;@1;)
      end
      i32.const 0
      local.get 0
      i32.const 16
      i32.add
      local.tee 1
      i64.load
      i64.store offset=1504
      i32.const 0
      local.get 1
      i32.const 8
      i32.add
      i64.load
      i64.store offset=1512
      i32.const 0
      i32.const 1
      i32.store offset=1488
      local.get 0
      i32.const 0
      i32.store offset=1068
    end
    local.get 0
    i32.load offset=1068
    local.set 1
    local.get 0
    i32.const 1072
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $pwrecord_fresh (type 16) (param i32) (result i32)
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
    i32.const 1
    i32.store
    local.get 1
    i32.load offset=8
    i32.const 50000
    i32.store offset=4
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i32.load offset=8
        i32.const 8
        i32.add
        i64.const 16
        call $sgx_read_rand
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.const 4
        i32.store offset=12
        br 1 (;@1;)
      end
      local.get 1
      i32.load offset=8
      i32.const 24
      i32.add
      local.tee 0
      i64.const 0
      i64.store align=4
      local.get 0
      i32.const 24
      i32.add
      i64.const 0
      i64.store align=4
      local.get 0
      i32.const 16
      i32.add
      i64.const 0
      i64.store align=4
      local.get 0
      i32.const 8
      i32.add
      i64.const 0
      i64.store align=4
      local.get 1
      i32.const 0
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
  (func $pwrecord_init_hash (type 17) (param i32 i32 i32)
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
    local.get 3
    i32.load offset=16
    local.get 3
    i32.load offset=12
    local.get 3
    i32.load offset=24
    i32.const 24
    i32.add
    call $pwrecord_compute_hash
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $pwrecord_encrypt (type 18) (param i32 i32 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=88
    local.get 4
    local.get 1
    i32.store offset=80
    local.get 4
    local.get 2
    i32.store offset=76
    local.get 4
    local.get 3
    i32.store offset=72
    local.get 4
    i32.const 16
    i32.add
    local.tee 3
    i64.const 0
    i64.store
    local.get 3
    i32.const 48
    i32.add
    i64.const 0
    i64.store
    local.get 3
    i32.const 40
    i32.add
    i64.const 0
    i64.store
    local.get 3
    i32.const 32
    i32.add
    i64.const 0
    i64.store
    local.get 3
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 3
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 3
    i32.const 8
    i32.add
    i64.const 0
    i64.store
    local.get 4
    i32.const 84
    i32.store offset=12
    local.get 4
    i32.load offset=88
    local.get 4
    i32.const 16
    i32.add
    call $pwrecord_encode
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=76
        local.get 4
        i32.load offset=12
        i32.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.const 1
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 4
        i32.load offset=80
        i64.const 12
        call $sgx_read_rand
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.const 4
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          i32.const 0
          i32.load offset=1488
          i32.eqz
          br_if 0 (;@3;)
          br 1 (;@2;)
        end
        i32.const 1076
        i32.const 145
        i32.const 1042
        i32.const 1024
        call $__assert
      end
      block  ;; label = @2
        i32.const 1504
        local.get 4
        i32.const 16
        i32.add
        i32.const 56
        local.get 4
        i32.load offset=80
        i32.const 12
        i32.add
        i32.const 16
        i32.add
        local.get 4
        i32.load offset=80
        i32.const 12
        i32.const 0
        i32.const 0
        local.get 4
        i32.load offset=80
        i32.const 12
        i32.add
        call $sgx_rijndael128GCM_encrypt
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.const 4
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 4
      i32.load offset=72
      local.get 4
      i32.load offset=12
      i32.store
      local.get 4
      i32.const 0
      i32.store offset=92
    end
    local.get 4
    i32.load offset=92
    local.set 3
    local.get 4
    i32.const 96
    i32.add
    global.set $__stack_pointer
    local.get 3)
  (func $pwrecord_clean (type 1) (param i32)
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
    i64.const 56
    call $mem_clean
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $read_region_data (type 18) (param i32 i32 i32 i32) (result i32)
    (local i32 i64 i64)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=88
    local.get 4
    local.get 1
    i32.store offset=80
    local.get 4
    local.get 2
    i32.store offset=76
    local.get 4
    local.get 3
    i32.store offset=72
    local.get 4
    i32.const 0
    i32.store offset=68
    local.get 4
    local.get 4
    i32.load offset=76
    i64.extend_i32_u
    i64.store offset=56
    local.get 4
    i64.const 4
    i64.store offset=48
    local.get 4
    i32.const 0
    i32.store offset=40
    local.get 4
    i64.const 32
    i64.store offset=32
    local.get 4
    i32.const 0
    i32.store offset=24
    local.get 4
    i32.const 0
    i32.store offset=16
    local.get 4
    i32.const 0
    i32.store offset=8
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.load offset=80
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=80
        local.get 4
        i64.load offset=56
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 4
        i32.load offset=72
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.load offset=72
        local.get 4
        i64.load offset=48
        call $sgx_is_within_enclave
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=56
          local.set 5
          br 1 (;@2;)
        end
        i64.const 0
        local.set 5
      end
      local.get 4
      local.get 4
      i64.load offset=32
      local.get 5
      i64.add
      local.tee 5
      i64.store offset=32
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i64.load offset=56
          local.set 6
          br 1 (;@2;)
        end
        i64.const 0
        local.set 6
      end
      block  ;; label = @2
        local.get 5
        local.get 6
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      block  ;; label = @2
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
          i64.load offset=48
          local.set 5
          br 1 (;@2;)
        end
        i64.const 0
        local.set 5
      end
      local.get 4
      local.get 4
      i64.load offset=32
      local.get 5
      i64.add
      local.tee 5
      i64.store offset=32
      block  ;; label = @2
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
          i64.load offset=48
          local.set 6
          br 1 (;@2;)
        end
        i64.const 0
        local.set 6
      end
      block  ;; label = @2
        local.get 5
        local.get 6
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 4
      local.get 4
      i64.load offset=32
      call $sgx_ocalloc
      i32.store offset=24
      block  ;; label = @2
        local.get 4
        i32.load offset=24
        i32.const 0
        i32.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        local.get 4
        i32.const 1
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 4
      local.get 4
      i32.load offset=24
      i32.store offset=40
      local.get 4
      local.get 4
      i32.load offset=24
      i64.extend_i32_u
      i64.const 32
      i64.add
      i32.wrap_i64
      i32.store offset=24
      local.get 4
      local.get 4
      i64.load offset=32
      i64.const 32
      i64.sub
      i64.store offset=32
      block  ;; label = @2
        block  ;; label = @3
          local.get 4
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=40
          local.get 4
          i32.load offset=24
          i32.store offset=4
          local.get 4
          local.get 4
          i32.load offset=24
          i32.store offset=16
          block  ;; label = @4
            local.get 4
            i64.load offset=56
            i64.const 0
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 2
            i32.store offset=92
            br 3 (;@1;)
          end
          local.get 4
          i32.load offset=16
          i32.const 0
          local.get 4
          i64.load offset=56
          i32.wrap_i64
          call $memset
          drop
          local.get 4
          local.get 4
          i32.load offset=24
          i64.extend_i32_u
          local.get 4
          i64.load offset=56
          i64.add
          i32.wrap_i64
          i32.store offset=24
          local.get 4
          local.get 4
          i64.load offset=32
          local.get 4
          i64.load offset=56
          i64.sub
          i64.store offset=32
          br 1 (;@2;)
        end
        local.get 4
        i32.load offset=40
        i32.const 0
        i32.store offset=4
      end
      local.get 4
      i32.load offset=40
      local.get 4
      i32.load offset=76
      i32.store offset=8
      block  ;; label = @2
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
          i32.load offset=40
          local.get 4
          i32.load offset=24
          i32.store offset=12
          local.get 4
          local.get 4
          i32.load offset=24
          i32.store offset=8
          block  ;; label = @4
            local.get 4
            i64.load offset=48
            i64.const 3
            i64.and
            i64.const 0
            i64.ne
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 2
            i32.store offset=92
            br 3 (;@1;)
          end
          local.get 4
          i32.load offset=8
          i32.const 0
          local.get 4
          i64.load offset=48
          i32.wrap_i64
          call $memset
          drop
          local.get 4
          local.get 4
          i32.load offset=24
          i64.extend_i32_u
          local.get 4
          i64.load offset=48
          i64.add
          i32.wrap_i64
          i32.store offset=24
          local.get 4
          local.get 4
          i64.load offset=32
          local.get 4
          i64.load offset=48
          i64.sub
          i64.store offset=32
          br 1 (;@2;)
        end
        local.get 4
        i32.load offset=40
        i32.const 0
        i32.store offset=12
      end
      local.get 4
      i32.const 2
      local.get 4
      i32.load offset=40
      call $sgx_ocall
      i32.store offset=68
      block  ;; label = @2
        local.get 4
        i32.load offset=68
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 4
          i32.load offset=88
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=88
          local.get 4
          i32.load offset=40
          i32.load
          i32.store
        end
        block  ;; label = @3
          local.get 4
          i32.load offset=80
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 4
            i32.load offset=80
            local.get 4
            i64.load offset=56
            local.get 4
            i32.load offset=16
            local.get 4
            i64.load offset=56
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 1
            i32.store offset=92
            br 3 (;@1;)
          end
        end
        block  ;; label = @3
          local.get 4
          i32.load offset=72
          i32.const 0
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 4
            i32.load offset=72
            local.get 4
            i64.load offset=48
            local.get 4
            i32.load offset=8
            local.get 4
            i64.load offset=48
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            local.get 4
            i32.const 1
            i32.store offset=92
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 4
      local.get 4
      i32.load offset=68
      i32.store offset=92
    end
    local.get 4
    i32.load offset=92
    local.set 3
    local.get 4
    i32.const 96
    i32.add
    global.set $__stack_pointer
    local.get 3)
  (func $pwrecord_compute_hash (type 8) (param i32 i32 i32 i32)
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
    i32.store offset=16
    local.get 4
    local.get 2
    i32.store offset=12
    local.get 4
    local.get 3
    i32.store offset=8
    local.get 4
    i32.load offset=16
    local.get 4
    i32.load offset=12
    i64.extend_i32_u
    local.get 4
    i32.load offset=24
    i32.const 8
    i32.add
    i64.const 16
    local.get 4
    i32.load offset=24
    i32.load offset=4
    local.get 4
    i32.load offset=8
    i64.const 32
    i32.const 1192
    call $cf_pbkdf2_hmac
    local.get 4
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $pwrecord_encode (type 0) (param i32 i32)
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
    i32.store
    local.get 2
    i32.load offset=8
    i32.load
    local.get 2
    i32.load
    call $write32_be
    local.get 2
    local.get 2
    i32.load
    i32.const 4
    i32.add
    i32.store
    local.get 2
    i32.load offset=8
    i32.load offset=4
    local.get 2
    i32.load
    call $write32_be
    local.get 2
    local.get 2
    i32.load
    i32.const 4
    i32.add
    i32.store
    local.get 2
    i32.load
    local.tee 1
    local.get 2
    i32.load offset=8
    i32.const 8
    i32.add
    local.tee 0
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    local.get 0
    i32.const 8
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 2
    local.get 2
    i32.load
    i32.const 16
    i32.add
    i32.store
    local.get 2
    i32.load
    local.tee 1
    local.get 2
    i32.load offset=8
    i32.const 24
    i32.add
    local.tee 0
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 24
    i32.add
    local.get 0
    i32.const 24
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 16
    i32.add
    local.get 0
    i32.const 16
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    local.get 0
    i32.const 8
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $write32_be (type 0) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 24
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 16
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 8
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=8
    local.get 2
    i32.load offset=12
    i32.const 255
    i32.and
    i32.store8)
  (func $cf_pbkdf2_hmac (type 19) (param i32 i64 i32 i64 i32 i32 i64 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 896
    i32.sub
    local.tee 8
    global.set $__stack_pointer
    local.get 8
    local.get 0
    i32.store offset=888
    local.get 8
    local.get 1
    i64.store offset=880
    local.get 8
    local.get 2
    i32.store offset=872
    local.get 8
    local.get 3
    i64.store offset=864
    local.get 8
    local.get 4
    i32.store offset=860
    local.get 8
    local.get 5
    i32.store offset=856
    local.get 8
    local.get 6
    i64.store offset=848
    local.get 8
    local.get 7
    i32.store offset=840
    local.get 8
    i32.const 1
    i32.store offset=836
    block  ;; label = @1
      local.get 8
      i32.load offset=860
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 8
        i32.load offset=856
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        i64.load offset=848
        i64.const 0
        i64.ne
        i32.const 1
        i32.and
        br_if 1 (;@1;)
      end
      call $abort
      unreachable
    end
    block  ;; label = @1
      local.get 8
      i32.load offset=840
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 8
    i32.const 40
    i32.add
    local.get 8
    i32.load offset=840
    local.get 8
    i32.load offset=888
    local.get 8
    i64.load offset=880
    call $cf_hmac_init
    block  ;; label = @1
      loop  ;; label = @2
        local.get 8
        i64.load offset=848
        i64.const 0
        i64.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 8
        i32.const 40
        i32.add
        local.get 8
        i32.load offset=836
        local.get 8
        i32.load offset=872
        local.get 8
        i64.load offset=864
        local.get 8
        i32.load offset=860
        local.get 8
        i32.const 768
        i32.add
        call $F
        local.get 8
        local.get 8
        i64.load offset=848
        i64.store offset=24
        local.get 8
        local.get 8
        i32.load offset=840
        i64.load
        i64.store offset=16
        block  ;; label = @3
          block  ;; label = @4
            local.get 8
            i64.load offset=24
            local.get 8
            i64.load offset=16
            i64.lt_u
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 8
            i64.load offset=24
            local.set 6
            br 1 (;@3;)
          end
          local.get 8
          i64.load offset=16
          local.set 6
        end
        local.get 8
        local.get 6
        i64.store offset=8
        local.get 8
        local.get 8
        i64.load offset=8
        i64.store offset=32
        local.get 8
        i32.load offset=856
        local.get 8
        i32.const 768
        i32.add
        local.get 8
        i64.load offset=32
        i32.wrap_i64
        call $memcpy
        drop
        local.get 8
        local.get 8
        i32.load offset=856
        local.get 8
        i64.load offset=32
        i32.wrap_i64
        i32.add
        i32.store offset=856
        local.get 8
        local.get 8
        i64.load offset=848
        local.get 8
        i64.load offset=32
        i64.sub
        i64.store offset=848
        local.get 8
        local.get 8
        i32.load offset=836
        i32.const 1
        i32.add
        i32.store offset=836
        br 0 (;@2;)
      end
    end
    local.get 8
    i32.const 896
    i32.add
    global.set $__stack_pointer)
  (func $pw_check (type 20) (param i32 i64 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=88
    local.get 4
    local.get 1
    i64.store offset=80
    local.get 4
    local.get 2
    i32.store offset=72
    local.get 4
    local.get 3
    i32.store offset=68
    local.get 4
    i32.const 8
    i32.add
    local.tee 3
    i64.const 0
    i64.store align=4
    local.get 3
    i32.const 48
    i32.add
    i64.const 0
    i64.store align=4
    local.get 3
    i32.const 40
    i32.add
    i64.const 0
    i64.store align=4
    local.get 3
    i32.const 32
    i32.add
    i64.const 0
    i64.store align=4
    local.get 3
    i32.const 24
    i32.add
    i64.const 0
    i64.store align=4
    local.get 3
    i32.const 16
    i32.add
    i64.const 0
    i64.store align=4
    local.get 3
    i32.const 8
    i32.add
    i64.const 0
    i64.store align=4
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=1488
        br_if 0 (;@2;)
        local.get 4
        call $fetch_region_key
        i32.store offset=4
        block  ;; label = @3
          local.get 4
          i32.load offset=4
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          local.get 4
          i32.load offset=4
          i32.store offset=92
          br 2 (;@1;)
        end
      end
      local.get 4
      local.get 4
      i32.const 8
      i32.add
      local.get 4
      i32.load offset=72
      local.get 4
      i32.load offset=68
      call $pwrecord_decrypt
      i32.store offset=4
      block  ;; label = @2
        local.get 4
        i32.load offset=4
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        local.get 4
        i32.load offset=4
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 4
      local.get 4
      i32.const 8
      i32.add
      local.get 4
      i32.load offset=88
      local.get 4
      i64.load offset=80
      i32.wrap_i64
      call $pwrecord_test_password
      i32.store offset=4
      local.get 4
      i32.const 8
      i32.add
      call $pwrecord_clean
      local.get 4
      local.get 4
      i32.load offset=4
      i32.store offset=92
    end
    local.get 4
    i32.load offset=92
    local.set 3
    local.get 4
    i32.const 96
    i32.add
    global.set $__stack_pointer
    local.get 3)
  (func $pwrecord_decrypt (type 5) (param i32 i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 96
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=88
    local.get 3
    local.get 1
    i32.store offset=80
    local.get 3
    local.get 2
    i32.store offset=76
    local.get 3
    i32.const 16
    i32.add
    local.tee 2
    i64.const 0
    i64.store
    local.get 2
    i32.const 48
    i32.add
    i64.const 0
    i64.store
    local.get 2
    i32.const 40
    i32.add
    i64.const 0
    i64.store
    local.get 2
    i32.const 32
    i32.add
    i64.const 0
    i64.store
    local.get 2
    i32.const 24
    i32.add
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
    local.get 3
    i32.const 56
    i32.store offset=12
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=1488
        i32.eqz
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      i32.const 1076
      i32.const 179
      i32.const 1059
      i32.const 1024
      call $__assert
    end
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.load offset=76
          i32.const 84
          i32.ne
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          i32.const 1504
          local.get 3
          i32.load offset=80
          i32.const 12
          i32.add
          i32.const 16
          i32.add
          i32.const 56
          local.get 3
          i32.const 16
          i32.add
          local.get 3
          i32.load offset=80
          i32.const 12
          i32.const 0
          i32.const 0
          local.get 3
          i32.load offset=80
          i32.const 12
          i32.add
          call $sgx_rijndael128GCM_decrypt
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 3
        i32.const 2
        i32.store offset=92
        br 1 (;@1;)
      end
      local.get 3
      local.get 3
      i32.load offset=88
      local.get 3
      i32.const 16
      i32.add
      call $pwrecord_decode
      i32.store offset=92
    end
    local.get 3
    i32.load offset=92
    local.set 2
    local.get 3
    i32.const 96
    i32.add
    global.set $__stack_pointer
    local.get 2)
  (func $pwrecord_test_password (type 5) (param i32 i32 i32) (result i32)
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
    i32.store offset=44
    local.get 3
    i32.load offset=56
    local.get 3
    i32.load offset=48
    local.get 3
    i32.load offset=44
    local.get 3
    call $pwrecord_compute_hash
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=56
        i32.const 24
        i32.add
        local.get 3
        i64.const 32
        call $mem_eq
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.const 0
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 3
      i32.const 3
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
  (func $pwrecord_decode (type 3) (param i32 i32) (result i32)
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
    i32.store
    local.get 2
    i32.load
    call $read32_be
    local.set 1
    local.get 2
    i32.load offset=8
    local.get 1
    i32.store
    local.get 2
    i32.load
    i32.const 4
    i32.add
    call $read32_be
    local.set 1
    local.get 2
    i32.load offset=8
    local.get 1
    i32.store offset=4
    local.get 2
    i32.load offset=8
    i32.const 8
    i32.add
    local.tee 1
    local.get 2
    i32.load
    i32.const 8
    i32.add
    local.tee 0
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    local.get 0
    i32.const 8
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 2
    i32.load offset=8
    i32.const 24
    i32.add
    local.tee 1
    local.get 2
    i32.load
    i32.const 8
    i32.add
    i32.const 16
    i32.add
    local.tee 0
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 24
    i32.add
    local.get 0
    i32.const 24
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 16
    i32.add
    local.get 0
    i32.const 16
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    local.get 0
    i32.const 8
    i32.add
    i64.load align=1
    i64.store align=1
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 2
          i32.load offset=8
          i32.load
          i32.const 1
          i32.ne
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=8
          i32.load offset=4
          br_if 1 (;@2;)
        end
        local.get 2
        i32.const 2
        i32.store offset=12
        br 1 (;@1;)
      end
      local.get 2
      i32.const 0
      i32.store offset=12
    end
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $mem_eq (type 21) (param i32 i32 i64) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 3
    local.get 0
    i32.store offset=40
    local.get 3
    local.get 1
    i32.store offset=32
    local.get 3
    local.get 2
    i64.store offset=24
    local.get 3
    local.get 3
    i32.load offset=40
    i32.store offset=16
    local.get 3
    local.get 3
    i32.load offset=32
    i32.store offset=8
    local.get 3
    i32.const 0
    i32.store8 offset=7
    block  ;; label = @1
      loop  ;; label = @2
        local.get 3
        local.get 3
        i64.load offset=24
        local.tee 2
        i64.const -1
        i64.add
        i64.store offset=24
        local.get 2
        i64.const 0
        i64.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        local.get 3
        i32.load offset=16
        local.tee 1
        i32.const 1
        i32.add
        i32.store offset=16
        local.get 1
        i32.load8_u
        local.set 1
        local.get 3
        local.get 3
        i32.load offset=8
        local.tee 0
        i32.const 1
        i32.add
        i32.store offset=8
        local.get 0
        i32.load8_u
        local.set 0
        local.get 3
        local.get 3
        i32.load8_u offset=7
        i32.const 255
        i32.and
        local.get 1
        i32.const 255
        i32.and
        local.get 0
        i32.const 255
        i32.and
        i32.xor
        i32.or
        i32.store8 offset=7
        br 0 (;@2;)
      end
    end
    local.get 3
    i32.load8_u offset=7
    i32.const 255
    i32.and
    i32.const 0
    i32.const 255
    i32.and
    i32.ne
    i32.const -1
    i32.xor
    i32.const 1
    i32.and)
  (func $read32_be (type 16) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.load offset=8
    i32.load8_u
    i32.const 255
    i32.and
    i32.const 24
    i32.shl
    local.get 1
    i32.load offset=8
    i32.load8_u offset=1
    i32.const 255
    i32.and
    i32.const 16
    i32.shl
    i32.or
    local.get 1
    i32.load offset=8
    i32.load8_u offset=2
    i32.const 255
    i32.and
    i32.const 8
    i32.shl
    i32.or
    local.get 1
    i32.load offset=8
    i32.load8_u offset=3
    i32.const 255
    i32.and
    i32.or)
  (func $cf_blockwise_accumulate (type 22) (param i32 i32 i64 i32 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 7
    global.set $__stack_pointer
    local.get 7
    local.get 0
    i32.store offset=56
    local.get 7
    local.get 1
    i32.store offset=48
    local.get 7
    local.get 2
    i64.store offset=40
    local.get 7
    local.get 3
    i32.store offset=32
    local.get 7
    local.get 4
    i64.store offset=24
    local.get 7
    local.get 5
    i32.store offset=16
    local.get 7
    local.get 6
    i32.store offset=8
    local.get 7
    i32.load offset=56
    local.get 7
    i32.load offset=48
    local.get 7
    i64.load offset=40
    local.get 7
    i32.load offset=32
    local.get 7
    i64.load offset=24
    local.get 7
    i32.load offset=16
    local.get 7
    i32.load offset=16
    local.get 7
    i32.load offset=8
    call $cf_blockwise_accumulate_final
    local.get 7
    i32.const 64
    i32.add
    global.set $__stack_pointer)
  (func $cf_blockwise_accumulate_final (type 23) (param i32 i32 i64 i32 i64 i32 i32 i32)
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
    i32.store offset=144
    local.get 8
    local.get 2
    i64.store offset=136
    local.get 8
    local.get 3
    i32.store offset=128
    local.get 8
    local.get 4
    i64.store offset=120
    local.get 8
    local.get 5
    i32.store offset=112
    local.get 8
    local.get 6
    i32.store offset=104
    local.get 8
    local.get 7
    i32.store offset=96
    local.get 8
    local.get 8
    i32.load offset=128
    i32.store offset=88
    block  ;; label = @1
      block  ;; label = @2
        local.get 8
        i32.load offset=152
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        i32.load offset=144
        i64.load
        local.get 8
        i64.load offset=136
        i64.lt_u
        i32.const 1
        i32.and
        br_if 1 (;@1;)
      end
      call $abort
      unreachable
    end
    block  ;; label = @1
      local.get 8
      i32.load offset=128
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      local.get 8
      i64.load offset=120
      i64.const 0
      i64.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 8
        i32.load offset=112
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        i32.load offset=96
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        br_if 1 (;@1;)
      end
      call $abort
      unreachable
    end
    block  ;; label = @1
      local.get 8
      i32.load offset=144
      i64.load
      i64.const 0
      i64.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 8
      i64.load offset=120
      i64.const 0
      i64.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 8
      local.get 8
      i64.load offset=136
      local.get 8
      i32.load offset=144
      i64.load
      i64.sub
      i64.store offset=80
      local.get 8
      local.get 8
      i64.load offset=80
      i64.store offset=64
      local.get 8
      local.get 8
      i64.load offset=120
      i64.store offset=56
      block  ;; label = @2
        block  ;; label = @3
          local.get 8
          i64.load offset=64
          local.get 8
          i64.load offset=56
          i64.lt_u
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 8
          i64.load offset=64
          local.set 4
          br 1 (;@2;)
        end
        local.get 8
        i64.load offset=56
        local.set 4
      end
      local.get 8
      local.get 4
      i64.store offset=48
      local.get 8
      local.get 8
      i64.load offset=48
      i64.store offset=72
      local.get 8
      i32.load offset=152
      local.get 8
      i32.load offset=144
      i64.load
      i32.wrap_i64
      i32.add
      local.get 8
      i32.load offset=88
      local.get 8
      i64.load offset=72
      i32.wrap_i64
      call $memcpy
      drop
      local.get 8
      local.get 8
      i32.load offset=88
      local.get 8
      i64.load offset=72
      i32.wrap_i64
      i32.add
      i32.store offset=88
      local.get 8
      local.get 8
      i64.load offset=120
      local.get 8
      i64.load offset=72
      i64.sub
      i64.store offset=120
      local.get 8
      i32.load offset=144
      local.tee 7
      local.get 7
      i64.load
      local.get 8
      i64.load offset=72
      i64.add
      i64.store
      block  ;; label = @2
        local.get 8
        i32.load offset=144
        i64.load
        local.get 8
        i64.load offset=136
        i64.eq
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 8
            i64.load offset=120
            i64.const 0
            i64.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 8
            i32.load offset=96
            local.get 8
            i32.load offset=152
            local.get 8
            i32.load offset=104
            call_indirect (type 0)
            br 1 (;@3;)
          end
          local.get 8
          i32.load offset=96
          local.get 8
          i32.load offset=152
          local.get 8
          i32.load offset=112
          call_indirect (type 0)
        end
        local.get 8
        i32.load offset=144
        i64.const 0
        i64.store
      end
    end
    block  ;; label = @1
      loop  ;; label = @2
        local.get 8
        i64.load offset=120
        local.get 8
        i64.load offset=136
        i64.ge_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          local.get 8
          i32.load offset=144
          i64.load
          i64.const 0
          i64.eq
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          call $abort
          unreachable
        end
        block  ;; label = @3
          block  ;; label = @4
            local.get 8
            i64.load offset=120
            local.get 8
            i64.load offset=136
            i64.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 8
            i32.load offset=96
            local.get 8
            i32.load offset=88
            local.get 8
            i32.load offset=104
            call_indirect (type 0)
            br 1 (;@3;)
          end
          local.get 8
          i32.load offset=96
          local.get 8
          i32.load offset=88
          local.get 8
          i32.load offset=112
          call_indirect (type 0)
        end
        local.get 8
        local.get 8
        i32.load offset=88
        local.get 8
        i64.load offset=136
        i32.wrap_i64
        i32.add
        i32.store offset=88
        local.get 8
        local.get 8
        i64.load offset=120
        local.get 8
        i64.load offset=136
        i64.sub
        i64.store offset=120
        br 0 (;@2;)
      end
    end
    block  ;; label = @1
      loop  ;; label = @2
        local.get 8
        i64.load offset=120
        i64.const 0
        i64.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 8
        local.get 8
        i64.load offset=136
        local.get 8
        i32.load offset=144
        i64.load
        i64.sub
        i64.store offset=40
        local.get 8
        local.get 8
        i64.load offset=40
        i64.store offset=24
        local.get 8
        local.get 8
        i64.load offset=120
        i64.store offset=16
        block  ;; label = @3
          block  ;; label = @4
            local.get 8
            i64.load offset=24
            local.get 8
            i64.load offset=16
            i64.lt_u
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 8
            i64.load offset=24
            local.set 4
            br 1 (;@3;)
          end
          local.get 8
          i64.load offset=16
          local.set 4
        end
        local.get 8
        local.get 4
        i64.store offset=8
        local.get 8
        local.get 8
        i64.load offset=8
        i64.store offset=32
        local.get 8
        i32.load offset=152
        local.get 8
        i32.load offset=144
        i64.load
        i32.wrap_i64
        i32.add
        local.get 8
        i32.load offset=88
        local.get 8
        i64.load offset=32
        i32.wrap_i64
        call $memcpy
        drop
        local.get 8
        local.get 8
        i32.load offset=88
        local.get 8
        i64.load offset=32
        i32.wrap_i64
        i32.add
        i32.store offset=88
        local.get 8
        local.get 8
        i64.load offset=120
        local.get 8
        i64.load offset=32
        i64.sub
        i64.store offset=120
        local.get 8
        i32.load offset=144
        local.tee 7
        local.get 7
        i64.load
        local.get 8
        i64.load offset=32
        i64.add
        i64.store
        block  ;; label = @3
          local.get 8
          i32.load offset=144
          i64.load
          local.get 8
          i64.load offset=136
          i64.lt_u
          i32.const 1
          i32.and
          br_if 0 (;@3;)
          call $abort
          unreachable
        end
        br 0 (;@2;)
      end
    end
    local.get 8
    i32.const 160
    i32.add
    global.set $__stack_pointer)
  (func $cf_blockwise_xor (type 24) (param i32 i32 i64 i32 i32 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 128
    i32.sub
    local.tee 8
    global.set $__stack_pointer
    local.get 8
    local.get 0
    i32.store offset=120
    local.get 8
    local.get 1
    i32.store offset=112
    local.get 8
    local.get 2
    i64.store offset=104
    local.get 8
    local.get 3
    i32.store offset=96
    local.get 8
    local.get 4
    i32.store offset=88
    local.get 8
    local.get 5
    i64.store offset=80
    local.get 8
    local.get 6
    i32.store offset=72
    local.get 8
    local.get 7
    i32.store offset=64
    local.get 8
    local.get 8
    i32.load offset=96
    i32.store offset=56
    local.get 8
    local.get 8
    i32.load offset=88
    i32.store offset=48
    block  ;; label = @1
      block  ;; label = @2
        local.get 8
        i32.load offset=120
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        i32.load offset=112
        i64.load
        local.get 8
        i64.load offset=104
        i64.lt_u
        i32.const 1
        i32.and
        br_if 1 (;@1;)
      end
      call $abort
      unreachable
    end
    block  ;; label = @1
      local.get 8
      i32.load offset=96
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      local.get 8
      i64.load offset=80
      i64.const 0
      i64.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 8
        i32.load offset=72
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        i32.load offset=64
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        br_if 1 (;@1;)
      end
      call $abort
      unreachable
    end
    block  ;; label = @1
      loop  ;; label = @2
        local.get 8
        i64.load offset=80
        i64.const 0
        i64.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          local.get 8
          i32.load offset=112
          i64.load
          i64.const 0
          i64.eq
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 8
          i32.load offset=64
          local.get 8
          i32.load offset=120
          local.get 8
          i32.load offset=72
          call_indirect (type 0)
          local.get 8
          i32.load offset=112
          local.get 8
          i64.load offset=104
          i64.store
        end
        local.get 8
        local.get 8
        i64.load offset=104
        local.get 8
        i32.load offset=112
        i64.load
        i64.sub
        i64.store offset=40
        local.get 8
        local.get 8
        i32.load offset=112
        i64.load
        i64.store offset=24
        local.get 8
        local.get 8
        i64.load offset=80
        i64.store offset=16
        block  ;; label = @3
          block  ;; label = @4
            local.get 8
            i64.load offset=24
            local.get 8
            i64.load offset=16
            i64.lt_u
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 8
            i64.load offset=24
            local.set 5
            br 1 (;@3;)
          end
          local.get 8
          i64.load offset=16
          local.set 5
        end
        local.get 8
        local.get 5
        i64.store offset=8
        local.get 8
        local.get 8
        i64.load offset=8
        i64.store offset=32
        local.get 8
        i32.load offset=48
        local.get 8
        i32.load offset=56
        local.get 8
        i32.load offset=120
        local.get 8
        i64.load offset=40
        i32.wrap_i64
        i32.add
        local.get 8
        i64.load offset=32
        call $xor_bb
        local.get 8
        i32.load offset=112
        local.tee 7
        local.get 7
        i64.load
        local.get 8
        i64.load offset=32
        i64.sub
        i64.store
        local.get 8
        local.get 8
        i64.load offset=80
        local.get 8
        i64.load offset=32
        i64.sub
        i64.store offset=80
        local.get 8
        local.get 8
        i32.load offset=48
        local.get 8
        i64.load offset=32
        i32.wrap_i64
        i32.add
        i32.store offset=48
        local.get 8
        local.get 8
        i32.load offset=56
        local.get 8
        i64.load offset=32
        i32.wrap_i64
        i32.add
        i32.store offset=56
        br 0 (;@2;)
      end
    end
    local.get 8
    i32.const 128
    i32.add
    global.set $__stack_pointer)
  (func $xor_bb (type 25) (param i32 i32 i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 4
    local.get 0
    i32.store offset=40
    local.get 4
    local.get 1
    i32.store offset=32
    local.get 4
    local.get 2
    i32.store offset=24
    local.get 4
    local.get 3
    i64.store offset=16
    local.get 4
    i64.const 0
    i64.store offset=8
    block  ;; label = @1
      loop  ;; label = @2
        local.get 4
        i64.load offset=8
        local.get 4
        i64.load offset=16
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.load offset=40
        local.get 4
        i64.load offset=8
        i32.wrap_i64
        i32.add
        local.get 4
        i32.load offset=32
        local.get 4
        i64.load offset=8
        i32.wrap_i64
        i32.add
        i32.load8_u
        i32.const 255
        i32.and
        local.get 4
        i32.load offset=24
        local.get 4
        i64.load offset=8
        i32.wrap_i64
        i32.add
        i32.load8_u
        i32.const 255
        i32.and
        i32.xor
        i32.store8
        local.get 4
        local.get 4
        i64.load offset=8
        i64.const 1
        i64.add
        i64.store offset=8
        br 0 (;@2;)
      end
    end)
  (func $cf_blockwise_acc_byte (type 22) (param i32 i32 i64 i32 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 112
    i32.sub
    local.tee 7
    global.set $__stack_pointer
    local.get 7
    local.get 0
    i32.store offset=104
    local.get 7
    local.get 1
    i32.store offset=96
    local.get 7
    local.get 2
    i64.store offset=88
    local.get 7
    local.get 3
    i32.store8 offset=87
    local.get 7
    local.get 4
    i64.store offset=72
    local.get 7
    local.get 5
    i32.store offset=64
    local.get 7
    local.get 6
    i32.store offset=56
    local.get 7
    i32.const 0
    i32.store offset=52
    block  ;; label = @1
      loop  ;; label = @2
        local.get 7
        i64.load offset=72
        i64.const 0
        i64.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 7
        local.get 7
        i32.load offset=96
        i64.load
        i64.store offset=40
        local.get 7
        local.get 7
        i64.load offset=72
        i64.store offset=24
        local.get 7
        local.get 7
        i64.load offset=88
        local.get 7
        i64.load offset=40
        i64.sub
        i64.store offset=16
        block  ;; label = @3
          block  ;; label = @4
            local.get 7
            i64.load offset=24
            local.get 7
            i64.load offset=16
            i64.lt_u
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 7
            i64.load offset=24
            local.set 4
            br 1 (;@3;)
          end
          local.get 7
          i64.load offset=16
          local.set 4
        end
        local.get 7
        local.get 4
        i64.store offset=8
        local.get 7
        local.get 7
        i64.load offset=8
        i64.store offset=32
        block  ;; label = @3
          local.get 7
          i32.load offset=52
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=104
          local.get 7
          i64.load offset=40
          i32.wrap_i64
          i32.add
          local.get 7
          i32.load8_u offset=87
          i32.const 255
          i32.and
          local.get 7
          i64.load offset=32
          i32.wrap_i64
          call $memset
          drop
        end
        block  ;; label = @3
          local.get 7
          i64.load offset=40
          i64.const 0
          i64.eq
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i64.load offset=32
          local.get 7
          i64.load offset=88
          i64.eq
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.const 1
          i32.store offset=52
        end
        block  ;; label = @3
          block  ;; label = @4
            local.get 7
            i64.load offset=40
            local.get 7
            i64.load offset=32
            i64.add
            local.get 7
            i64.load offset=88
            i64.eq
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 7
            i32.load offset=56
            local.get 7
            i32.load offset=104
            local.get 7
            i32.load offset=64
            call_indirect (type 0)
            local.get 7
            i32.load offset=96
            i64.const 0
            i64.store
            br 1 (;@3;)
          end
          local.get 7
          i32.load offset=96
          local.tee 6
          local.get 6
          i64.load
          local.get 7
          i64.load offset=32
          i64.add
          i64.store
        end
        local.get 7
        local.get 7
        i64.load offset=72
        local.get 7
        i64.load offset=32
        i64.sub
        i64.store offset=72
        br 0 (;@2;)
      end
    end
    local.get 7
    i32.const 112
    i32.add
    global.set $__stack_pointer)
  (func $cf_blockwise_acc_pad (type 26) (param i32 i32 i64 i32 i32 i32 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 64
    i32.sub
    local.tee 9
    global.set $__stack_pointer
    local.get 9
    local.get 0
    i32.store offset=56
    local.get 9
    local.get 1
    i32.store offset=48
    local.get 9
    local.get 2
    i64.store offset=40
    local.get 9
    local.get 3
    i32.store8 offset=39
    local.get 9
    local.get 4
    i32.store8 offset=38
    local.get 9
    local.get 5
    i32.store8 offset=37
    local.get 9
    local.get 6
    i64.store offset=24
    local.get 9
    local.get 7
    i32.store offset=16
    local.get 9
    local.get 8
    i32.store offset=8
    local.get 9
    i64.load offset=24
    local.tee 6
    i32.wrap_i64
    local.set 8
    block  ;; label = @1
      block  ;; label = @2
        local.get 6
        i64.const 2
        i64.gt_u
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 8
              br_table 0 (;@5;) 1 (;@4;) 2 (;@3;) 0 (;@5;)
            end
            br 3 (;@1;)
          end
          local.get 9
          local.get 9
          i32.load8_u offset=39
          i32.const 255
          i32.and
          local.get 9
          i32.load8_u offset=37
          i32.const 255
          i32.and
          i32.xor
          i32.store8 offset=39
          local.get 9
          i32.load offset=56
          local.get 9
          i32.load offset=48
          local.get 9
          i64.load offset=40
          local.get 9
          i32.const 39
          i32.add
          i64.const 1
          local.get 9
          i32.load offset=16
          local.get 9
          i32.load offset=8
          call $cf_blockwise_accumulate
          br 2 (;@1;)
        end
        local.get 9
        i32.load offset=56
        local.get 9
        i32.load offset=48
        local.get 9
        i64.load offset=40
        local.get 9
        i32.const 39
        i32.add
        i64.const 1
        local.get 9
        i32.load offset=16
        local.get 9
        i32.load offset=8
        call $cf_blockwise_accumulate
        local.get 9
        i32.load offset=56
        local.get 9
        i32.load offset=48
        local.get 9
        i64.load offset=40
        local.get 9
        i32.const 37
        i32.add
        i64.const 1
        local.get 9
        i32.load offset=16
        local.get 9
        i32.load offset=8
        call $cf_blockwise_accumulate
        br 1 (;@1;)
      end
      local.get 9
      i32.load offset=56
      local.get 9
      i32.load offset=48
      local.get 9
      i64.load offset=40
      local.get 9
      i32.const 39
      i32.add
      i64.const 1
      local.get 9
      i32.load offset=16
      local.get 9
      i32.load offset=8
      call $cf_blockwise_accumulate
      block  ;; label = @2
        block  ;; label = @3
          local.get 9
          i32.load8_u offset=37
          i32.const 255
          i32.and
          local.get 9
          i32.load8_u offset=38
          i32.const 255
          i32.and
          i32.ne
          i32.const 1
          i32.and
          i32.eqz
          br_if 0 (;@3;)
          local.get 9
          i32.load offset=56
          local.get 9
          i32.load offset=48
          local.get 9
          i64.load offset=40
          local.get 9
          i32.load8_u offset=38
          i32.const 255
          i32.and
          local.get 9
          i64.load offset=24
          i64.const 2
          i64.sub
          local.get 9
          i32.load offset=16
          local.get 9
          i32.load offset=8
          call $cf_blockwise_acc_byte
          local.get 9
          i32.load offset=56
          local.get 9
          i32.load offset=48
          local.get 9
          i64.load offset=40
          local.get 9
          i32.const 37
          i32.add
          i64.const 1
          local.get 9
          i32.load offset=16
          local.get 9
          i32.load offset=8
          call $cf_blockwise_accumulate
          br 1 (;@2;)
        end
        local.get 9
        i32.load offset=56
        local.get 9
        i32.load offset=48
        local.get 9
        i64.load offset=40
        local.get 9
        i32.load8_u offset=38
        i32.const 255
        i32.and
        local.get 9
        i64.load offset=24
        i64.const 1
        i64.sub
        local.get 9
        i32.load offset=16
        local.get 9
        i32.load offset=8
        call $cf_blockwise_acc_byte
      end
    end
    local.get 9
    i32.const 64
    i32.add
    global.set $__stack_pointer)
  (func $sgx_pw_region_enroll (type 16) (param i32) (result i32)
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
      i32.load offset=8
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
        i32.load offset=20
        call $pw_region_enroll
        local.set 0
        local.get 1
        i32.load offset=32
        local.get 0
        i32.store
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
  (func $sgx_pw_setup (type 16) (param i32) (result i32)
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
      i32.load offset=4
      i32.store offset=88
      local.get 1
      local.get 1
      i32.load offset=96
      i32.load offset=8
      i32.store offset=84
      local.get 1
      local.get 1
      i32.load offset=84
      i64.extend_i32_u
      i64.store offset=72
      local.get 1
      i32.const 0
      i32.store offset=64
      local.get 1
      local.get 1
      i32.load offset=96
      i32.load offset=12
      i32.store offset=56
      local.get 1
      local.get 1
      i32.load offset=96
      i32.load offset=16
      i32.store offset=52
      local.get 1
      local.get 1
      i32.load offset=52
      i64.extend_i32_u
      i64.store offset=40
      local.get 1
      i32.const 0
      i32.store offset=32
      local.get 1
      local.get 1
      i32.load offset=96
      i32.load offset=20
      i32.store offset=24
      local.get 1
      i64.const 4
      i64.store offset=16
      local.get 1
      i32.const 0
      i32.store offset=8
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
        i64.load offset=16
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
          local.tee 0
          i32.store offset=32
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
            i32.store offset=92
            br 2 (;@2;)
          end
          local.get 1
          i32.load offset=32
          i32.const 0
          local.get 1
          i64.load offset=40
          i32.wrap_i64
          call $memset
          drop
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
            i32.store offset=92
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
            i32.store offset=92
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
        i32.load offset=64
        local.get 1
        i32.load offset=84
        local.get 1
        i32.load offset=32
        local.get 1
        i32.load offset=52
        local.get 1
        i32.load offset=8
        call $pw_setup
        local.set 0
        local.get 1
        i32.load offset=96
        local.get 0
        i32.store
        block  ;; label = @3
          local.get 1
          i32.load offset=32
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
            i32.load offset=32
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
            i32.store offset=92
            br 2 (;@2;)
          end
        end
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
  (func $sgx_pw_check (type 16) (param i32) (result i32)
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
            i32.store offset=60
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
            i32.store offset=60
            br 2 (;@2;)
          end
        end
        local.get 1
        i32.load offset=32
        local.get 1
        i64.load offset=48
        local.get 1
        i32.load
        local.get 1
        i32.load offset=20
        call $pw_check
        local.set 0
        local.get 1
        i32.load offset=64
        local.get 0
        i32.store
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
  (func $emit_debug (type 16) (param i32) (result i32)
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
  (func $cf_hmac_init (type 25) (param i32 i32 i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 288
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=280
    local.get 4
    local.get 1
    i32.store offset=272
    local.get 4
    local.get 2
    i32.store offset=264
    local.get 4
    local.get 3
    i64.store offset=256
    block  ;; label = @1
      local.get 4
      i32.load offset=280
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      local.get 4
      i32.load offset=272
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 4
    i32.load offset=280
    i64.const 728
    call $mem_clean.11
    local.get 4
    i32.load offset=280
    local.get 4
    i32.load offset=272
    i32.store
    block  ;; label = @1
      local.get 4
      i64.load offset=256
      local.get 4
      i32.load offset=272
      i64.load offset=8
      i64.gt_u
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 4
        i32.load offset=272
        i64.load
        local.get 4
        i32.load offset=272
        i64.load offset=8
        i64.le_u
        i32.const 1
        i32.and
        br_if 0 (;@2;)
        call $abort
        unreachable
      end
      local.get 4
      i32.load offset=272
      local.get 4
      i32.load offset=264
      local.get 4
      i64.load offset=256
      local.get 4
      i32.const 128
      i32.add
      call $cf_hash
      local.get 4
      local.get 4
      i32.const 128
      i32.add
      i32.store offset=264
      local.get 4
      local.get 4
      i32.load offset=272
      i64.load
      i64.store offset=256
    end
    block  ;; label = @1
      local.get 4
      i32.const 128
      i32.add
      local.get 4
      i32.load offset=264
      i32.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      i32.const 128
      i32.add
      local.get 4
      i32.load offset=264
      local.get 4
      i64.load offset=256
      i32.wrap_i64
      call $memcpy
      drop
    end
    block  ;; label = @1
      local.get 4
      i32.load offset=272
      i64.load offset=8
      local.get 4
      i64.load offset=256
      i64.gt_u
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      i32.const 128
      i32.add
      local.get 4
      i64.load offset=256
      i32.wrap_i64
      i32.add
      i32.const 0
      local.get 4
      i32.load offset=272
      i64.load offset=8
      local.get 4
      i64.load offset=256
      i64.sub
      i32.wrap_i64
      call $memset
      drop
    end
    local.get 4
    local.get 4
    i32.const 128
    i32.add
    i32.const 54
    i32.const 255
    i32.and
    local.get 4
    i32.load offset=272
    i64.load offset=8
    call $xor_b8
    local.get 4
    i32.load offset=280
    i32.const 8
    i32.add
    local.get 4
    i32.load offset=272
    i32.load offset=16
    call_indirect (type 1)
    local.get 4
    i32.load offset=280
    i32.const 8
    i32.add
    local.get 4
    local.get 4
    i32.load offset=272
    i64.load offset=8
    local.get 4
    i32.load offset=272
    i32.load offset=20
    call_indirect (type 2)
    local.get 4
    local.get 4
    i32.const 128
    i32.add
    i32.const 92
    i32.const 255
    i32.and
    local.get 4
    i32.load offset=272
    i64.load offset=8
    call $xor_b8
    local.get 4
    i32.load offset=280
    i32.const 368
    i32.add
    local.get 4
    i32.load offset=272
    i32.load offset=16
    call_indirect (type 1)
    local.get 4
    i32.load offset=280
    i32.const 368
    i32.add
    local.get 4
    local.get 4
    i32.load offset=272
    i64.load offset=8
    local.get 4
    i32.load offset=272
    i32.load offset=20
    call_indirect (type 2)
    local.get 4
    i64.const 128
    call $mem_clean.11
    local.get 4
    i32.const 128
    i32.add
    i64.const 128
    call $mem_clean.11
    local.get 4
    i32.const 288
    i32.add
    global.set $__stack_pointer)
  (func $F (type 27) (param i32 i32 i32 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 848
    i32.sub
    local.tee 6
    global.set $__stack_pointer
    local.get 6
    local.get 0
    i32.store offset=840
    local.get 6
    local.get 1
    i32.store offset=836
    local.get 6
    local.get 2
    i32.store offset=832
    local.get 6
    local.get 3
    i64.store offset=824
    local.get 6
    local.get 4
    i32.store offset=820
    local.get 6
    local.get 5
    i32.store offset=816
    local.get 6
    local.get 6
    i32.load offset=840
    i32.load
    i64.load
    i64.store offset=744
    local.get 6
    i32.load offset=836
    local.get 6
    i32.const 740
    i32.add
    call $write32_be.7
    local.get 6
    i32.const 8
    i32.add
    local.get 6
    i32.load offset=840
    i32.const 728
    call $memcpy
    drop
    local.get 6
    i32.const 8
    i32.add
    local.get 6
    i32.load offset=832
    local.get 6
    i64.load offset=824
    call $cf_hmac_update
    local.get 6
    i32.const 8
    i32.add
    local.get 6
    i32.const 740
    i32.add
    i64.const 4
    call $cf_hmac_update
    local.get 6
    i32.const 8
    i32.add
    local.get 6
    i32.const 752
    i32.add
    call $cf_hmac_finish
    local.get 6
    i32.load offset=816
    local.get 6
    i32.const 752
    i32.add
    local.get 6
    i64.load offset=744
    i32.wrap_i64
    call $memcpy
    drop
    local.get 6
    i32.const 1
    i32.store offset=4
    block  ;; label = @1
      loop  ;; label = @2
        local.get 6
        i32.load offset=4
        local.get 6
        i32.load offset=820
        i32.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 6
        i32.const 8
        i32.add
        local.get 6
        i32.load offset=840
        i32.const 728
        call $memcpy
        drop
        local.get 6
        i32.const 8
        i32.add
        local.get 6
        i32.const 752
        i32.add
        local.get 6
        i64.load offset=744
        call $cf_hmac_update
        local.get 6
        i32.const 8
        i32.add
        local.get 6
        i32.const 752
        i32.add
        call $cf_hmac_finish
        local.get 6
        i32.load offset=816
        local.get 6
        i32.load offset=816
        local.get 6
        i32.const 752
        i32.add
        local.get 6
        i64.load offset=744
        call $xor_bb.8
        local.get 6
        local.get 6
        i32.load offset=4
        i32.const 1
        i32.add
        i32.store offset=4
        br 0 (;@2;)
      end
    end
    local.get 6
    i32.const 848
    i32.add
    global.set $__stack_pointer)
  (func $write32_be.7 (type 0) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 24
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 16
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 8
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=8
    local.get 2
    i32.load offset=12
    i32.const 255
    i32.and
    i32.store8)
  (func $cf_hmac_update (type 2) (param i32 i32 i64)
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
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.load offset=24
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=24
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        br_if 1 (;@1;)
      end
      call $abort
      unreachable
    end
    local.get 3
    i32.load offset=24
    i32.const 8
    i32.add
    local.get 3
    i32.load offset=16
    local.get 3
    i64.load offset=8
    local.get 3
    i32.load offset=24
    i32.load
    i32.load offset=20
    call_indirect (type 2)
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $cf_hmac_finish (type 0) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=72
    local.get 2
    local.get 1
    i32.store offset=64
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        i32.load offset=72
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i32.load offset=72
        i32.load
        i32.const 0
        i32.ne
        i32.const 1
        i32.and
        br_if 1 (;@1;)
      end
      call $abort
      unreachable
    end
    block  ;; label = @1
      local.get 2
      i32.load offset=64
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 2
    i32.load offset=72
    i32.const 8
    i32.add
    local.get 2
    local.get 2
    i32.load offset=72
    i32.load
    i32.load offset=24
    call_indirect (type 0)
    local.get 2
    i32.load offset=72
    i32.const 368
    i32.add
    local.get 2
    local.get 2
    i32.load offset=72
    i32.load
    i64.load
    local.get 2
    i32.load offset=72
    i32.load
    i32.load offset=20
    call_indirect (type 2)
    local.get 2
    i32.load offset=72
    i32.const 368
    i32.add
    local.get 2
    i32.load offset=64
    local.get 2
    i32.load offset=72
    i32.load
    i32.load offset=24
    call_indirect (type 0)
    local.get 2
    i32.load offset=72
    i64.const 728
    call $mem_clean.11
    local.get 2
    i32.const 80
    i32.add
    global.set $__stack_pointer)
  (func $xor_bb.8 (type 25) (param i32 i32 i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 4
    local.get 0
    i32.store offset=40
    local.get 4
    local.get 1
    i32.store offset=32
    local.get 4
    local.get 2
    i32.store offset=24
    local.get 4
    local.get 3
    i64.store offset=16
    local.get 4
    i64.const 0
    i64.store offset=8
    block  ;; label = @1
      loop  ;; label = @2
        local.get 4
        i64.load offset=8
        local.get 4
        i64.load offset=16
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.load offset=40
        local.get 4
        i64.load offset=8
        i32.wrap_i64
        i32.add
        local.get 4
        i32.load offset=32
        local.get 4
        i64.load offset=8
        i32.wrap_i64
        i32.add
        i32.load8_u
        i32.const 255
        i32.and
        local.get 4
        i32.load offset=24
        local.get 4
        i64.load offset=8
        i32.wrap_i64
        i32.add
        i32.load8_u
        i32.const 255
        i32.and
        i32.xor
        i32.store8
        local.get 4
        local.get 4
        i64.load offset=8
        i64.const 1
        i64.add
        i64.store offset=8
        br 0 (;@2;)
      end
    end)
  (func $mem_clean.11 (type 14) (param i32 i64)
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
    block  ;; label = @1
      local.get 2
      i64.load
      i64.const 0
      i64.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      i32.load offset=8
      i32.const 0
      local.get 2
      i64.load
      i32.wrap_i64
      call $memset
      drop
      local.get 2
      i32.load offset=8
      i32.load8_u
      drop
    end
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $cf_hash (type 28) (param i32 i32 i64 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 400
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=392
    local.get 4
    local.get 1
    i32.store offset=384
    local.get 4
    local.get 2
    i64.store offset=376
    local.get 4
    local.get 3
    i32.store offset=368
    block  ;; label = @1
      local.get 4
      i32.load offset=392
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 4
    i32.const 8
    i32.add
    local.get 4
    i32.load offset=392
    i32.load offset=16
    call_indirect (type 1)
    local.get 4
    i32.const 8
    i32.add
    local.get 4
    i32.load offset=384
    local.get 4
    i64.load offset=376
    local.get 4
    i32.load offset=392
    i32.load offset=20
    call_indirect (type 2)
    local.get 4
    i32.const 8
    i32.add
    local.get 4
    i32.load offset=368
    local.get 4
    i32.load offset=392
    i32.load offset=24
    call_indirect (type 0)
    local.get 4
    i32.const 8
    i32.add
    i64.const 360
    call $mem_clean.18
    local.get 4
    i32.const 400
    i32.add
    global.set $__stack_pointer)
  (func $xor_b8 (type 25) (param i32 i32 i32 i64)
    (local i32)
    global.get $__stack_pointer
    i32.const 48
    i32.sub
    local.tee 4
    local.get 0
    i32.store offset=40
    local.get 4
    local.get 1
    i32.store offset=32
    local.get 4
    local.get 2
    i32.store8 offset=31
    local.get 4
    local.get 3
    i64.store offset=16
    local.get 4
    i64.const 0
    i64.store offset=8
    block  ;; label = @1
      loop  ;; label = @2
        local.get 4
        i64.load offset=8
        local.get 4
        i64.load offset=16
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        local.get 4
        i32.load offset=40
        local.get 4
        i64.load offset=8
        i32.wrap_i64
        i32.add
        local.get 4
        i32.load offset=32
        local.get 4
        i64.load offset=8
        i32.wrap_i64
        i32.add
        i32.load8_u
        i32.const 255
        i32.and
        local.get 4
        i32.load8_u offset=31
        i32.const 255
        i32.and
        i32.xor
        i32.store8
        local.get 4
        local.get 4
        i64.load offset=8
        i64.const 1
        i64.add
        i64.store offset=8
        br 0 (;@2;)
      end
    end)
  (func $cf_hmac (type 29) (param i32 i64 i32 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 784
    i32.sub
    local.tee 6
    global.set $__stack_pointer
    local.get 6
    local.get 0
    i32.store offset=776
    local.get 6
    local.get 1
    i64.store offset=768
    local.get 6
    local.get 2
    i32.store offset=760
    local.get 6
    local.get 3
    i64.store offset=752
    local.get 6
    local.get 4
    i32.store offset=744
    local.get 6
    local.get 5
    i32.store offset=736
    block  ;; label = @1
      local.get 6
      i32.load offset=744
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    block  ;; label = @1
      local.get 6
      i32.load offset=736
      i32.const 0
      i32.ne
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 6
    i32.const 8
    i32.add
    local.get 6
    i32.load offset=736
    local.get 6
    i32.load offset=776
    local.get 6
    i64.load offset=768
    call $cf_hmac_init
    local.get 6
    i32.const 8
    i32.add
    local.get 6
    i32.load offset=760
    local.get 6
    i64.load offset=752
    call $cf_hmac_update
    local.get 6
    i32.const 8
    i32.add
    local.get 6
    i32.load offset=744
    call $cf_hmac_finish
    local.get 6
    i32.const 784
    i32.add
    global.set $__stack_pointer)
  (func $mem_clean.18 (type 14) (param i32 i64)
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
    block  ;; label = @1
      local.get 2
      i64.load
      i64.const 0
      i64.ne
      i32.const 1
      i32.and
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      i32.load offset=8
      i32.const 0
      local.get 2
      i64.load
      i32.wrap_i64
      call $memset
      drop
      local.get 2
      i32.load offset=8
      i32.load8_u
      drop
    end
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha224_init (type 1) (param i32)
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
    i32.const 0
    i32.const 112
    call $memset
    drop
    local.get 1
    i32.load offset=8
    i32.const -1056596264
    i32.store
    local.get 1
    i32.load offset=8
    i32.const 914150663
    i32.store offset=4
    local.get 1
    i32.load offset=8
    i32.const 812702999
    i32.store offset=8
    local.get 1
    i32.load offset=8
    i32.const -150054599
    i32.store offset=12
    local.get 1
    i32.load offset=8
    i32.const -4191439
    i32.store offset=16
    local.get 1
    i32.load offset=8
    i32.const 1750603025
    i32.store offset=20
    local.get 1
    i32.load offset=8
    i32.const 1694076839
    i32.store offset=24
    local.get 1
    i32.load offset=8
    i32.const -1090891868
    i32.store offset=28
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha224_update (type 2) (param i32 i32 i64)
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
    local.get 3
    i32.load offset=24
    local.get 3
    i32.load offset=16
    local.get 3
    i64.load offset=8
    call $cf_sha256_update
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha256_update (type 2) (param i32 i32 i64)
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
    local.get 3
    i32.load offset=24
    i32.const 32
    i32.add
    local.get 3
    i32.load offset=24
    i32.const 104
    i32.add
    i64.const 64
    local.get 3
    i32.load offset=16
    local.get 3
    i64.load offset=8
    i32.const 1
    local.get 3
    i32.load offset=24
    call $cf_blockwise_accumulate
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha224_digest (type 0) (param i32 i32)
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
    i32.load offset=40
    local.get 2
    call $cf_sha256_digest
    local.get 2
    i32.load offset=32
    local.tee 1
    local.get 2
    local.tee 0
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 24
    i32.add
    local.get 0
    i32.const 24
    i32.add
    i32.load align=1
    i32.store align=1
    local.get 1
    i32.const 16
    i32.add
    local.get 0
    i32.const 16
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    local.get 0
    i32.const 8
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 2
    i32.const 48
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha256_digest (type 0) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 128
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=120
    local.get 2
    local.get 1
    i32.store offset=112
    local.get 2
    local.get 2
    i32.load offset=120
    i32.const 112
    call $memcpy
    drop
    local.get 2
    local.get 2
    i32.load offset=112
    call $cf_sha256_digest_final
    local.get 2
    i32.const 128
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha256_digest_final (type 0) (param i32 i32)
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
    local.get 2
    i32.load offset=40
    i32.load offset=96
    i64.extend_i32_u
    i64.store
    local.get 2
    local.get 2
    i64.load
    i64.const 6
    i64.shl
    local.get 2
    i32.load offset=40
    i64.load offset=104
    i64.add
    i64.store
    local.get 2
    local.get 2
    i64.load
    i64.const 3
    i64.shl
    i64.store offset=8
    local.get 2
    i64.const 64
    local.get 2
    i64.load
    i64.const 8
    i64.add
    i64.const 63
    i64.and
    i64.sub
    i64.store offset=24
    local.get 2
    i32.load offset=40
    i32.const 32
    i32.add
    local.get 2
    i32.load offset=40
    i32.const 104
    i32.add
    i64.const 64
    i32.const 128
    i32.const 255
    i32.and
    i32.const 0
    i32.const 255
    i32.and
    i32.const 0
    i32.const 255
    i32.and
    local.get 2
    i64.load offset=24
    i32.const 1
    local.get 2
    i32.load offset=40
    call $cf_blockwise_acc_pad
    local.get 2
    i64.load offset=8
    local.get 2
    i32.const 16
    i32.add
    call $write64_be
    local.get 2
    i32.load offset=40
    local.get 2
    i32.const 16
    i32.add
    i64.const 8
    call $cf_sha256_update
    block  ;; label = @1
      local.get 2
      i32.load offset=40
      i64.load offset=104
      i64.const 0
      i64.eq
      i32.const 1
      i32.and
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 2
    i32.load offset=40
    i32.load
    local.get 2
    i32.load offset=32
    call $write32_be.19
    local.get 2
    i32.load offset=40
    i32.load offset=4
    local.get 2
    i32.load offset=32
    i32.const 4
    i32.add
    call $write32_be.19
    local.get 2
    i32.load offset=40
    i32.load offset=8
    local.get 2
    i32.load offset=32
    i32.const 8
    i32.add
    call $write32_be.19
    local.get 2
    i32.load offset=40
    i32.load offset=12
    local.get 2
    i32.load offset=32
    i32.const 12
    i32.add
    call $write32_be.19
    local.get 2
    i32.load offset=40
    i32.load offset=16
    local.get 2
    i32.load offset=32
    i32.const 16
    i32.add
    call $write32_be.19
    local.get 2
    i32.load offset=40
    i32.load offset=20
    local.get 2
    i32.load offset=32
    i32.const 20
    i32.add
    call $write32_be.19
    local.get 2
    i32.load offset=40
    i32.load offset=24
    local.get 2
    i32.load offset=32
    i32.const 24
    i32.add
    call $write32_be.19
    local.get 2
    i32.load offset=40
    i32.load offset=28
    local.get 2
    i32.load offset=32
    i32.const 28
    i32.add
    call $write32_be.19
    local.get 2
    i32.load offset=40
    i32.const 0
    i32.const 112
    call $memset
    drop
    local.get 2
    i32.const 48
    i32.add
    global.set $__stack_pointer)
  (func $sha256_update_block (type 0) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 160
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    local.get 0
    i32.store offset=152
    local.get 2
    local.get 1
    i32.store offset=144
    local.get 2
    local.get 2
    i32.load offset=152
    i32.store offset=136
    local.get 2
    local.get 2
    i32.load offset=136
    i32.load
    i32.store offset=60
    local.get 2
    local.get 2
    i32.load offset=136
    i32.load offset=4
    i32.store offset=56
    local.get 2
    local.get 2
    i32.load offset=136
    i32.load offset=8
    i32.store offset=52
    local.get 2
    local.get 2
    i32.load offset=136
    i32.load offset=12
    i32.store offset=48
    local.get 2
    local.get 2
    i32.load offset=136
    i32.load offset=16
    i32.store offset=44
    local.get 2
    local.get 2
    i32.load offset=136
    i32.load offset=20
    i32.store offset=40
    local.get 2
    local.get 2
    i32.load offset=136
    i32.load offset=24
    i32.store offset=36
    local.get 2
    local.get 2
    i32.load offset=136
    i32.load offset=28
    i32.store offset=32
    local.get 2
    i64.const 0
    i64.store offset=8
    block  ;; label = @1
      loop  ;; label = @2
        local.get 2
        i64.load offset=8
        i64.const 64
        i64.lt_u
        i32.const 1
        i32.and
        i32.eqz
        br_if 1 (;@1;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 2
            i64.load offset=8
            i64.const 16
            i64.lt_u
            i32.const 1
            i32.and
            i32.eqz
            br_if 0 (;@4;)
            local.get 2
            local.get 2
            i32.load offset=144
            call $read32_be.20
            local.tee 1
            i32.store offset=28
            local.get 2
            i32.const 64
            i32.add
            local.get 2
            i64.load offset=8
            i32.wrap_i64
            i32.const 2
            i32.shl
            i32.add
            local.get 1
            i32.store
            local.get 2
            local.get 2
            i32.load offset=144
            i32.const 4
            i32.add
            i32.store offset=144
            br 1 (;@3;)
          end
          local.get 2
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 2
          i64.sub
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.const 17
          call $rotr32
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 2
          i64.sub
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.const 19
          call $rotr32
          i32.xor
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 2
          i64.sub
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.const 10
          i32.shr_u
          i32.xor
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 7
          i64.sub
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.add
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 15
          i64.sub
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.const 7
          call $rotr32
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 15
          i64.sub
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.const 18
          call $rotr32
          i32.xor
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 15
          i64.sub
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.const 3
          i32.shr_u
          i32.xor
          i32.add
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 16
          i64.sub
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          i32.load
          i32.add
          i32.store offset=28
          local.get 2
          i32.const 64
          i32.add
          local.get 2
          i64.load offset=8
          i64.const 15
          i64.and
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          local.get 2
          i32.load offset=28
          i32.store
        end
        local.get 2
        local.get 2
        i32.load offset=32
        local.get 2
        i32.load offset=44
        i32.const 6
        call $rotr32
        local.get 2
        i32.load offset=44
        i32.const 11
        call $rotr32
        i32.xor
        local.get 2
        i32.load offset=44
        i32.const 25
        call $rotr32
        i32.xor
        i32.add
        local.get 2
        i32.load offset=44
        local.get 2
        i32.load offset=40
        i32.and
        local.get 2
        i32.load offset=44
        i32.const -1
        i32.xor
        local.get 2
        i32.load offset=36
        i32.and
        i32.xor
        i32.add
        i32.const 1232
        local.get 2
        i64.load offset=8
        i32.wrap_i64
        i32.const 2
        i32.shl
        i32.add
        i32.load
        i32.add
        local.get 2
        i32.load offset=28
        i32.add
        i32.store offset=24
        local.get 2
        local.get 2
        i32.load offset=60
        i32.const 2
        call $rotr32
        local.get 2
        i32.load offset=60
        i32.const 13
        call $rotr32
        i32.xor
        local.get 2
        i32.load offset=60
        i32.const 22
        call $rotr32
        i32.xor
        local.get 2
        i32.load offset=60
        local.get 2
        i32.load offset=56
        i32.and
        local.get 2
        i32.load offset=60
        local.get 2
        i32.load offset=52
        i32.and
        i32.xor
        local.get 2
        i32.load offset=56
        local.get 2
        i32.load offset=52
        i32.and
        i32.xor
        i32.add
        i32.store offset=20
        local.get 2
        local.get 2
        i32.load offset=36
        i32.store offset=32
        local.get 2
        local.get 2
        i32.load offset=40
        i32.store offset=36
        local.get 2
        local.get 2
        i32.load offset=44
        i32.store offset=40
        local.get 2
        local.get 2
        i32.load offset=48
        local.get 2
        i32.load offset=24
        i32.add
        i32.store offset=44
        local.get 2
        local.get 2
        i32.load offset=52
        i32.store offset=48
        local.get 2
        local.get 2
        i32.load offset=56
        i32.store offset=52
        local.get 2
        local.get 2
        i32.load offset=60
        i32.store offset=56
        local.get 2
        local.get 2
        i32.load offset=24
        local.get 2
        i32.load offset=20
        i32.add
        i32.store offset=60
        local.get 2
        local.get 2
        i64.load offset=8
        i64.const 1
        i64.add
        i64.store offset=8
        br 0 (;@2;)
      end
    end
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load
    local.get 2
    i32.load offset=60
    i32.add
    i32.store
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load offset=4
    local.get 2
    i32.load offset=56
    i32.add
    i32.store offset=4
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load offset=8
    local.get 2
    i32.load offset=52
    i32.add
    i32.store offset=8
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load offset=12
    local.get 2
    i32.load offset=48
    i32.add
    i32.store offset=12
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load offset=16
    local.get 2
    i32.load offset=44
    i32.add
    i32.store offset=16
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load offset=20
    local.get 2
    i32.load offset=40
    i32.add
    i32.store offset=20
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load offset=24
    local.get 2
    i32.load offset=36
    i32.add
    i32.store offset=24
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load offset=28
    local.get 2
    i32.load offset=32
    i32.add
    i32.store offset=28
    local.get 2
    i32.load offset=136
    local.tee 1
    local.get 1
    i32.load offset=96
    i32.const 1
    i32.add
    i32.store offset=96
    local.get 2
    i32.const 160
    i32.add
    global.set $__stack_pointer)
  (func $write64_be (type 30) (param i64 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    local.get 0
    i64.store offset=8
    local.get 2
    local.get 1
    i32.store
    local.get 2
    i64.load offset=8
    local.set 0
    local.get 2
    local.get 2
    i32.load
    local.tee 1
    i32.const 1
    i32.add
    i32.store
    local.get 1
    local.get 0
    i64.const 56
    i64.shr_u
    i64.const 255
    i64.and
    i32.wrap_i64
    i32.store8
    local.get 2
    i64.load offset=8
    local.set 0
    local.get 2
    local.get 2
    i32.load
    local.tee 1
    i32.const 1
    i32.add
    i32.store
    local.get 1
    local.get 0
    i64.const 48
    i64.shr_u
    i64.const 255
    i64.and
    i32.wrap_i64
    i32.store8
    local.get 2
    i64.load offset=8
    local.set 0
    local.get 2
    local.get 2
    i32.load
    local.tee 1
    i32.const 1
    i32.add
    i32.store
    local.get 1
    local.get 0
    i64.const 40
    i64.shr_u
    i64.const 255
    i64.and
    i32.wrap_i64
    i32.store8
    local.get 2
    i64.load offset=8
    local.set 0
    local.get 2
    local.get 2
    i32.load
    local.tee 1
    i32.const 1
    i32.add
    i32.store
    local.get 1
    local.get 0
    i64.const 32
    i64.shr_u
    i64.const 255
    i64.and
    i32.wrap_i64
    i32.store8
    local.get 2
    i64.load offset=8
    local.set 0
    local.get 2
    local.get 2
    i32.load
    local.tee 1
    i32.const 1
    i32.add
    i32.store
    local.get 1
    local.get 0
    i64.const 24
    i64.shr_u
    i64.const 255
    i64.and
    i32.wrap_i64
    i32.store8
    local.get 2
    i64.load offset=8
    local.set 0
    local.get 2
    local.get 2
    i32.load
    local.tee 1
    i32.const 1
    i32.add
    i32.store
    local.get 1
    local.get 0
    i64.const 16
    i64.shr_u
    i64.const 255
    i64.and
    i32.wrap_i64
    i32.store8
    local.get 2
    i64.load offset=8
    local.set 0
    local.get 2
    local.get 2
    i32.load
    local.tee 1
    i32.const 1
    i32.add
    i32.store
    local.get 1
    local.get 0
    i64.const 8
    i64.shr_u
    i64.const 255
    i64.and
    i32.wrap_i64
    i32.store8
    local.get 2
    i32.load
    local.get 2
    i64.load offset=8
    i64.const 255
    i64.and
    i32.wrap_i64
    i32.store8)
  (func $write32_be.19 (type 0) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 24
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 16
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=12
    local.set 1
    local.get 2
    local.get 2
    i32.load offset=8
    local.tee 0
    i32.const 1
    i32.add
    i32.store offset=8
    local.get 0
    local.get 1
    i32.const 8
    i32.shr_u
    i32.const 255
    i32.and
    i32.store8
    local.get 2
    i32.load offset=8
    local.get 2
    i32.load offset=12
    i32.const 255
    i32.and
    i32.store8)
  (func $read32_be.20 (type 16) (param i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 1
    local.get 0
    i32.store offset=8
    local.get 1
    i32.load offset=8
    i32.load8_u
    i32.const 255
    i32.and
    i32.const 24
    i32.shl
    local.get 1
    i32.load offset=8
    i32.load8_u offset=1
    i32.const 255
    i32.and
    i32.const 16
    i32.shl
    i32.or
    local.get 1
    i32.load offset=8
    i32.load8_u offset=2
    i32.const 255
    i32.and
    i32.const 8
    i32.shl
    i32.or
    local.get 1
    i32.load offset=8
    i32.load8_u offset=3
    i32.const 255
    i32.and
    i32.or)
  (func $rotr32 (type 3) (param i32 i32) (result i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    local.get 0
    i32.store offset=12
    local.get 2
    local.get 1
    i32.store offset=8
    local.get 2
    i32.load offset=12
    local.get 2
    i32.load offset=8
    i32.shr_u
    local.get 2
    i32.load offset=12
    i32.const 32
    local.get 2
    i32.load offset=8
    i32.sub
    i32.shl
    i32.or)
  (func $cf_sha256_init (type 1) (param i32)
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
    i32.const 0
    i32.const 112
    call $memset
    drop
    local.get 1
    i32.load offset=8
    i32.const 1779033703
    i32.store
    local.get 1
    i32.load offset=8
    i32.const -1150833019
    i32.store offset=4
    local.get 1
    i32.load offset=8
    i32.const 1013904242
    i32.store offset=8
    local.get 1
    i32.load offset=8
    i32.const -1521486534
    i32.store offset=12
    local.get 1
    i32.load offset=8
    i32.const 1359893119
    i32.store offset=16
    local.get 1
    i32.load offset=8
    i32.const -1694144372
    i32.store offset=20
    local.get 1
    i32.load offset=8
    i32.const 528734635
    i32.store offset=24
    local.get 1
    i32.load offset=8
    i32.const 1541459225
    i32.store offset=28
    local.get 1
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha224_digest_final (type 0) (param i32 i32)
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
    i32.load offset=40
    local.get 2
    call $cf_sha256_digest_final
    local.get 2
    i32.load offset=32
    local.tee 1
    local.get 2
    local.tee 0
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 24
    i32.add
    local.get 0
    i32.const 24
    i32.add
    i32.load align=1
    i32.store align=1
    local.get 1
    i32.const 16
    i32.add
    local.get 0
    i32.const 16
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    local.get 0
    i32.const 8
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 2
    i32.const 48
    i32.add
    global.set $__stack_pointer)
  (table (;0;) 11 11 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 67056))
  (global (;1;) i32 (i32.const 1192))
  (global (;2;) i32 (i32.const 1104))
  (global (;3;) i32 (i32.const 1136))
  (global (;4;) i32 (i32.const 1160))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 1520))
  (global (;7;) i32 (i32.const 1024))
  (global (;8;) i32 (i32.const 67056))
  (global (;9;) i32 (i32.const 0))
  (global (;10;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "pw_region_enroll" (func $pw_region_enroll))
  (export "write_region_data" (func $write_region_data))
  (export "pw_setup" (func $pw_setup))
  (export "read_region_data" (func $read_region_data))
  (export "cf_sha256" (global 1))
  (export "cf_pbkdf2_hmac" (func $cf_pbkdf2_hmac))
  (export "pw_check" (func $pw_check))
  (export "cf_blockwise_accumulate" (func $cf_blockwise_accumulate))
  (export "cf_blockwise_accumulate_final" (func $cf_blockwise_accumulate_final))
  (export "cf_blockwise_xor" (func $cf_blockwise_xor))
  (export "cf_blockwise_acc_byte" (func $cf_blockwise_acc_byte))
  (export "cf_blockwise_acc_pad" (func $cf_blockwise_acc_pad))
  (export "emit_debug" (func $emit_debug))
  (export "cf_hmac_init" (func $cf_hmac_init))
  (export "cf_hmac_update" (func $cf_hmac_update))
  (export "cf_hmac_finish" (func $cf_hmac_finish))
  (export "cf_hash" (func $cf_hash))
  (export "cf_hmac" (func $cf_hmac))
  (export "cf_sha224_init" (func $cf_sha224_init))
  (export "cf_sha224_update" (func $cf_sha224_update))
  (export "cf_sha256_update" (func $cf_sha256_update))
  (export "cf_sha224_digest" (func $cf_sha224_digest))
  (export "cf_sha256_digest" (func $cf_sha256_digest))
  (export "cf_sha256_digest_final" (func $cf_sha256_digest_final))
  (export "cf_sha256_init" (func $cf_sha256_init))
  (export "cf_sha224_digest_final" (func $cf_sha224_digest_final))
  (export "g_ecall_table" (global 2))
  (export "g_dyn_entry_table" (global 3))
  (export "cf_sha224" (global 4))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 5))
  (export "__data_end" (global 6))
  (export "__global_base" (global 7))
  (export "__heap_base" (global 8))
  (export "__memory_base" (global 9))
  (export "__table_base" (global 10))
  (elem (;0;) (i32.const 1) func $sha256_update_block $sgx_pw_region_enroll $sgx_pw_setup $sgx_pw_check $cf_sha224_init $cf_sha224_update $cf_sha224_digest $cf_sha256_init $cf_sha256_update $cf_sha256_digest)
  (data $.rodata (i32.const 1024) "g_have_region_key\00pwrecord_encrypt\00pwrecord_decrypt\00pwenclave/pwenclave.c\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\1c\00\00\00\00\00\00\00@\00\00\00\00\00\00\00\05\00\00\00\06\00\00\00\07\00\00\00\00\00\00\00 \00\00\00\00\00\00\00@\00\00\00\00\00\00\00\08\00\00\00\09\00\00\00\0a\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\98/\8aB\91D7q\cf\fb\c0\b5\a5\db\b5\e9[\c2V9\f1\11\f1Y\a4\82?\92\d5^\1c\ab\98\aa\07\d8\01[\83\12\be\851$\c3}\0cUt]\ber\fe\b1\de\80\a7\06\dc\9bt\f1\9b\c1\c1i\9b\e4\86G\be\ef\c6\9d\c1\0f\cc\a1\0c$o,\e9-\aa\84tJ\dc\a9\b0\5c\da\88\f9vRQ>\98m\c61\a8\c8'\03\b0\c7\7fY\bf\f3\0b\e0\c6G\91\a7\d5Qc\ca\06g))\14\85\0a\b7'8!\1b.\fcm,M\13\0d8STs\0ae\bb\0ajv.\c9\c2\81\85,r\92\a1\e8\bf\a2Kf\1a\a8p\8bK\c2\a3Ql\c7\19\e8\92\d1$\06\99\d6\855\0e\f4p\a0j\10\16\c1\a4\19\08l7\1eLwH'\b5\bc\b04\b3\0c\1c9J\aa\d8NO\ca\9c[\f3o.h\ee\82\8ftoc\a5x\14x\c8\84\08\02\c7\8c\fa\ff\be\90\eblP\a4\f7\a3\f9\be\f2xq\c6"))
