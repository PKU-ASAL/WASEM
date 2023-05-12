(module
  (type (;0;) (func (param i32 i32)))
  (type (;1;) (func (param i32)))
  (type (;2;) (func (param i32 i32 i64)))
  (type (;3;) (func (param i32 i32) (result i32)))
  (type (;4;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32 i32 i32) (result i32)))
  (type (;6;) (func))
  (type (;7;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;8;) (func (param i32 i64) (result i32)))
  (type (;9;) (func (param i32 i32 i32 i32)))
  (type (;10;) (func (param i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;11;) (func (param i64) (result i32)))
  (type (;12;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;13;) (func (param i32) (result i64)))
  (type (;14;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;15;) (func (param i32 i64 i32 i64 i32 i32 i64 i32)))
  (type (;16;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;17;) (func (param i32 i32 i64 i32 i64 i32 i32)))
  (type (;18;) (func (param i32 i32 i64 i32 i64 i32 i32 i32)))
  (type (;19;) (func (param i32 i32 i64 i32 i32 i64 i32 i32)))
  (type (;20;) (func (param i32 i32 i64 i32 i32 i32 i64 i32 i32)))
  (type (;21;) (func (param i32) (result i32)))
  (type (;22;) (func (param i32 i32 i32 i64)))
  (type (;23;) (func (param i32 i32 i64 i32)))
  (type (;24;) (func (param i32 i64 i32 i64 i32 i32)))
  (import "env" "sgx_calc_sealed_data_size" (func $sgx_calc_sealed_data_size (type 3)))
  (import "env" "sgx_seal_data" (func $sgx_seal_data (type 4)))
  (import "env" "memset" (func $memset (type 5)))
  (import "env" "__stack_chk_fail" (func $__stack_chk_fail (type 6)))
  (import "env" "sgx_unseal_data" (func $sgx_unseal_data (type 7)))
  (import "env" "sgx_read_rand" (func $sgx_read_rand (type 8)))
  (import "env" "__assert" (func $__assert (type 9)))
  (import "env" "sgx_rijndael128GCM_encrypt" (func $sgx_rijndael128GCM_encrypt (type 10)))
  (import "env" "sgx_rijndael128GCM_decrypt" (func $sgx_rijndael128GCM_decrypt (type 10)))
  (import "env" "memcpy" (func $memcpy (type 5)))
  (import "env" "abort" (func $abort (type 6)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 8)))
  (import "env" "malloc" (func $malloc (type 11)))
  (import "env" "memcpy_s" (func $memcpy_s (type 12)))
  (import "env" "free" (func $free (type 1)))
  (import "env" "strlen" (func $strlen (type 13)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 8)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 11)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 3)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 6)))
  (func $__wasm_call_ctors (type 6))
  (func $pw_region_enroll (type 3) (param i32 i32) (result i32)
    (local i32 i32)
    global.get $__stack_pointer
    i32.const 1056
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=1052
    i32.const 1
    local.set 3
    block  ;; label = @1
      local.get 1
      i32.const 16
      i32.ne
      br_if 0 (;@1;)
      i32.const 4
      local.set 3
      i32.const 0
      i32.const 16
      call $sgx_calc_sealed_data_size
      local.tee 1
      i32.const 1024
      i32.gt_u
      br_if 0 (;@1;)
      i32.const 0
      i32.const 0
      i32.const 16
      local.get 0
      local.get 1
      local.get 2
      i32.const 16
      i32.add
      call $sgx_seal_data
      br_if 0 (;@1;)
      local.get 2
      i32.const 12
      i32.add
      local.get 2
      i32.const 16
      i32.add
      local.get 1
      call $write_region_data
      br_if 0 (;@1;)
      local.get 2
      i32.const 16
      i32.add
      i32.const 0
      i32.const 1024
      call $memset
      drop
      local.get 2
      i32.load8_u offset=16
      drop
      local.get 2
      i32.load offset=12
      local.set 3
    end
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=1052
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 1056
    i32.add
    global.set $__stack_pointer
    local.get 3)
  (func $write_region_data (type 5) (param i32 i32 i32) (result i32)
    (local i64 i64 i32 i32 i32)
    local.get 2
    i64.extend_i32_u
    local.set 3
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        br_if 0 (;@2;)
        i64.const 0
        local.set 4
        br 1 (;@1;)
      end
      local.get 3
      local.set 4
      local.get 1
      local.get 3
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 1
    local.set 5
    block  ;; label = @1
      local.get 4
      i64.const 24
      i64.add
      call $sgx_ocalloc
      local.tee 6
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.eqz
          br_if 0 (;@3;)
          local.get 6
          local.get 6
          i32.const 24
          i32.add
          local.tee 7
          i32.store offset=8
          local.get 7
          local.get 4
          local.get 1
          local.get 3
          call $memcpy_s
          i32.eqz
          br_if 1 (;@2;)
          br 2 (;@1;)
        end
        local.get 6
        i32.const 0
        i32.store offset=8
      end
      local.get 6
      local.get 2
      i32.store offset=16
      i32.const 1
      local.get 6
      call $sgx_ocall
      local.tee 5
      br_if 0 (;@1;)
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 6
      i32.load
      i32.store
    end
    call $sgx_ocfree
    local.get 5)
  (func $pw_setup (type 7) (param i32 i32 i32 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 1136
    i32.sub
    local.tee 5
    global.set $__stack_pointer
    local.get 5
    i32.const 0
    i32.load
    i32.store offset=1132
    local.get 5
    i32.const 72
    i32.add
    i64.const 0
    i64.store
    local.get 5
    i32.const 64
    i32.add
    i64.const 0
    i64.store
    local.get 5
    i32.const 56
    i32.add
    i64.const 0
    i64.store
    local.get 5
    i32.const 48
    i32.add
    i64.const 0
    i64.store
    local.get 5
    i32.const 40
    i32.add
    i64.const 0
    i64.store
    local.get 5
    i32.const 32
    i32.add
    local.tee 6
    i64.const 0
    i64.store
    local.get 5
    i64.const 0
    i64.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load8_u offset=1488
        br_if 0 (;@2;)
        i32.const 1
        local.set 7
        block  ;; label = @3
          local.get 5
          i32.const 20
          i32.add
          local.get 5
          i32.const 96
          i32.add
          i32.const 1024
          local.get 5
          i32.const 16
          i32.add
          call $read_region_data
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=20
          local.tee 7
          br_if 0 (;@3;)
          local.get 5
          i32.const 16
          i32.store offset=12
          i32.const 2
          local.set 7
          local.get 5
          i32.const 96
          i32.add
          i32.const 0
          i32.const 0
          local.get 5
          i32.const 80
          i32.add
          local.get 5
          i32.const 12
          i32.add
          call $sgx_unseal_data
          br_if 0 (;@3;)
          local.get 5
          i32.load offset=12
          i32.const 16
          i32.ne
          br_if 0 (;@3;)
          i32.const 0
          local.set 7
          i32.const 0
          local.get 5
          i64.load offset=88
          i64.store offset=1512
          i32.const 0
          local.get 5
          i64.load offset=80
          i64.store offset=1504
          i32.const 0
          i32.const 1
          i32.store8 offset=1488
        end
        local.get 7
        br_if 1 (;@1;)
      end
      local.get 5
      i64.const 214748364800001
      i64.store offset=24
      i32.const 4
      local.set 7
      local.get 6
      i64.const 16
      call $sgx_read_rand
      br_if 0 (;@1;)
      local.get 5
      i32.const 24
      i32.add
      i32.const 48
      i32.add
      local.tee 8
      i64.const 0
      i64.store
      local.get 5
      i32.const 24
      i32.add
      i32.const 40
      i32.add
      local.tee 9
      i64.const 0
      i64.store
      local.get 5
      i32.const 24
      i32.add
      i32.const 32
      i32.add
      local.tee 10
      i64.const 0
      i64.store
      local.get 5
      i64.const 0
      i64.store offset=48
      local.get 0
      local.get 1
      i64.extend_i32_u
      local.get 6
      i64.const 16
      local.get 5
      i32.load offset=28
      local.get 5
      i32.const 24
      i32.add
      i32.const 24
      i32.add
      local.tee 1
      i64.const 32
      i32.const 1192
      call $cf_pbkdf2_hmac
      local.get 5
      i32.const 96
      i32.add
      i32.const 32
      i32.add
      local.get 10
      i64.load
      i64.store align=4
      local.get 5
      i32.const 96
      i32.add
      i32.const 40
      i32.add
      local.get 9
      i64.load
      i64.store
      local.get 5
      i32.const 96
      i32.add
      i32.const 48
      i32.add
      local.get 8
      i64.load
      i64.store align=4
      local.get 5
      i32.const 96
      i32.add
      i32.const 16
      i32.add
      local.get 6
      i32.const 8
      i32.add
      i64.load align=4
      i64.store align=4
      local.get 5
      local.get 5
      i64.load offset=48
      i64.store offset=120
      local.get 5
      local.get 6
      i64.load align=4
      i64.store offset=104
      local.get 5
      local.get 5
      i32.load offset=24
      local.tee 7
      i32.const 24
      i32.shl
      local.get 7
      i32.const 8
      i32.shl
      i32.const 16711680
      i32.and
      i32.or
      local.get 7
      i32.const 8
      i32.shr_u
      i32.const 65280
      i32.and
      local.get 7
      i32.const 24
      i32.shr_u
      i32.or
      i32.or
      i32.store offset=96
      local.get 5
      local.get 5
      i32.load offset=28
      local.tee 7
      i32.const 24
      i32.shl
      local.get 7
      i32.const 8
      i32.shl
      i32.const 16711680
      i32.and
      i32.or
      local.get 7
      i32.const 8
      i32.shr_u
      i32.const 65280
      i32.and
      local.get 7
      i32.const 24
      i32.shr_u
      i32.or
      i32.or
      i32.store offset=100
      i32.const 1
      local.set 7
      block  ;; label = @2
        local.get 3
        i32.const 84
        i32.lt_u
        br_if 0 (;@2;)
        i32.const 4
        local.set 7
        local.get 2
        i64.const 12
        call $sgx_read_rand
        br_if 0 (;@2;)
        block  ;; label = @3
          i32.const 0
          i32.load8_u offset=1488
          br_if 0 (;@3;)
          i32.const 1076
          i32.const 145
          i32.const 1042
          i32.const 1024
          call $__assert
        end
        i32.const 1504
        local.get 5
        i32.const 96
        i32.add
        i32.const 56
        local.get 2
        i32.const 28
        i32.add
        local.get 2
        i32.const 12
        i32.const 0
        i32.const 0
        local.get 2
        i32.const 12
        i32.add
        call $sgx_rijndael128GCM_encrypt
        br_if 0 (;@2;)
        local.get 4
        i32.const 84
        i32.store
        i32.const 0
        local.set 7
      end
      local.get 5
      i32.const 24
      i32.add
      i32.const 8
      i32.add
      i64.const 0
      i64.store
      local.get 5
      i32.const 24
      i32.add
      i32.const 16
      i32.add
      i64.const 0
      i64.store
      local.get 1
      i64.const 0
      i64.store
      local.get 10
      i64.const 0
      i64.store
      local.get 9
      i64.const 0
      i64.store
      local.get 8
      i64.const 0
      i64.store
      local.get 5
      i64.const 0
      i64.store offset=24
      local.get 5
      i32.load8_u offset=24
      drop
    end
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 5
      i32.load offset=1132
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 5
    i32.const 1136
    i32.add
    global.set $__stack_pointer
    local.get 7)
  (func $read_region_data (type 14) (param i32 i32 i32 i32) (result i32)
    (local i64 i64 i32 i32 i32 i32)
    local.get 2
    i64.extend_i32_u
    local.set 4
    block  ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      local.get 4
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        br_if 0 (;@2;)
        i64.const 0
        local.set 5
        br 1 (;@1;)
      end
      i64.const 4
      local.set 5
      local.get 3
      i64.const 4
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 1
    local.set 6
    block  ;; label = @1
      local.get 5
      local.get 4
      i64.const 32
      i64.add
      i64.const 32
      local.get 1
      select
      i64.add
      call $sgx_ocalloc
      local.tee 7
      i32.eqz
      br_if 0 (;@1;)
      local.get 7
      i64.extend_i32_u
      i64.const 32
      i64.add
      local.tee 5
      i32.wrap_i64
      local.set 8
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          local.get 8
          i32.store offset=8
          local.get 8
          i32.const 0
          local.get 4
          i32.wrap_i64
          call $memset
          drop
          local.get 5
          local.get 4
          i64.add
          i32.wrap_i64
          local.set 9
          br 1 (;@2;)
        end
        local.get 7
        i32.const 0
        i32.store offset=8
        local.get 8
        local.set 9
        i32.const 0
        local.set 8
      end
      local.get 7
      local.get 2
      i32.store offset=16
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          local.get 9
          i32.store offset=24
          local.get 9
          i32.const 0
          i32.store align=1
          br 1 (;@2;)
        end
        i32.const 0
        local.set 9
        local.get 7
        i32.const 0
        i32.store offset=24
      end
      block  ;; label = @2
        i32.const 2
        local.get 7
        call $sgx_ocall
        local.tee 2
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          local.get 7
          i32.load
          i32.store
        end
        block  ;; label = @3
          local.get 1
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 4
          local.get 8
          local.get 4
          call $memcpy_s
          br_if 2 (;@1;)
        end
        local.get 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i64.const 4
        local.get 9
        i64.const 4
        call $memcpy_s
        br_if 1 (;@1;)
      end
      local.get 2
      local.set 6
    end
    call $sgx_ocfree
    local.get 6)
  (func $cf_pbkdf2_hmac (type 15) (param i32 i64 i32 i64 i32 i32 i64 i32)
    (local i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i32 i64 i64 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 1616
    i32.sub
    local.tee 8
    global.set $__stack_pointer
    local.get 8
    i32.const 0
    i32.load
    i32.store offset=1612
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        i64.const 0
        i64.eq
        br_if 0 (;@2;)
        local.get 7
        i32.eqz
        br_if 0 (;@2;)
        local.get 8
        i32.const 8
        i32.add
        local.get 7
        local.get 0
        local.get 1
        call $cf_hmac_init
        local.get 4
        i32.const 2
        i32.lt_u
        local.set 9
        i32.const 1
        local.set 10
        loop  ;; label = @3
          local.get 8
          i32.load offset=8
          i64.load
          local.set 11
          local.get 8
          local.get 10
          i32.const 24
          i32.shl
          local.get 10
          i32.const 8
          i32.shl
          i32.const 16711680
          i32.and
          i32.or
          local.get 10
          i32.const 8
          i32.shr_u
          i32.const 65280
          i32.and
          local.get 10
          i32.const 24
          i32.shr_u
          i32.or
          i32.or
          i32.store offset=4 align=1
          local.get 8
          i32.const 808
          i32.add
          local.get 8
          i32.const 8
          i32.add
          i32.const 728
          call $memcpy
          drop
          local.get 8
          i32.const 808
          i32.add
          local.get 2
          local.get 3
          call $cf_hmac_update
          local.get 8
          i32.const 808
          i32.add
          local.get 8
          i32.const 4
          i32.add
          i64.const 4
          call $cf_hmac_update
          local.get 8
          i32.const 808
          i32.add
          local.get 8
          i32.const 1536
          i32.add
          call $cf_hmac_finish
          local.get 8
          i32.const 736
          i32.add
          local.get 8
          i32.const 1536
          i32.add
          local.get 11
          i32.wrap_i64
          call $memcpy
          drop
          block  ;; label = @4
            local.get 9
            br_if 0 (;@4;)
            local.get 11
            i64.const 24
            i64.and
            local.set 12
            local.get 11
            i64.const -32
            i64.and
            local.set 13
            i64.const 0
            local.get 11
            i64.const -8
            i64.and
            local.tee 14
            i64.sub
            local.set 15
            local.get 11
            i64.const -32
            i64.add
            local.tee 16
            i64.const 5
            i64.shr_u
            i64.const 1
            i64.add
            local.tee 1
            i64.const 1
            i64.and
            local.set 17
            i64.const 0
            local.get 1
            i64.const 1152921504606846974
            i64.and
            i64.sub
            local.set 18
            i32.const 1
            local.set 19
            loop  ;; label = @5
              local.get 8
              i32.const 808
              i32.add
              local.get 8
              i32.const 8
              i32.add
              i32.const 728
              call $memcpy
              drop
              local.get 8
              i32.const 808
              i32.add
              local.get 8
              i32.const 1536
              i32.add
              local.get 11
              call $cf_hmac_update
              local.get 8
              i32.const 808
              i32.add
              local.get 8
              i32.const 1536
              i32.add
              call $cf_hmac_finish
              block  ;; label = @6
                local.get 11
                i64.eqz
                br_if 0 (;@6;)
                i64.const 0
                local.set 20
                block  ;; label = @7
                  local.get 11
                  i64.const 8
                  i64.lt_u
                  br_if 0 (;@7;)
                  i64.const 0
                  local.set 21
                  block  ;; label = @8
                    local.get 11
                    i64.const 32
                    i64.lt_u
                    br_if 0 (;@8;)
                    i64.const 0
                    local.set 1
                    block  ;; label = @9
                      local.get 16
                      i64.const 32
                      i64.lt_u
                      br_if 0 (;@9;)
                      i64.const 0
                      local.set 1
                      i32.const 0
                      local.set 22
                      local.get 18
                      local.set 20
                      loop  ;; label = @10
                        local.get 8
                        i32.const 736
                        i32.add
                        local.get 22
                        i32.add
                        local.tee 0
                        local.get 8
                        i32.const 1536
                        i32.add
                        local.get 22
                        i32.add
                        local.tee 23
                        i32.load8_u offset=8
                        local.get 0
                        i32.load8_u offset=8
                        i32.xor
                        i32.store8 offset=8
                        local.get 0
                        local.get 23
                        i32.load8_u offset=4
                        local.get 0
                        i32.load8_u offset=4
                        i32.xor
                        i32.store8 offset=4
                        local.get 0
                        local.get 23
                        i32.load8_u offset=2
                        local.get 0
                        i32.load8_u offset=2
                        i32.xor
                        i32.store8 offset=2
                        local.get 0
                        local.get 23
                        i32.load8_u offset=1
                        local.get 0
                        i32.load8_u offset=1
                        i32.xor
                        i32.store8 offset=1
                        local.get 0
                        local.get 23
                        i32.load8_u
                        local.get 0
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 31
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 31
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 30
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 30
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 29
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 29
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 27
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 27
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 26
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 26
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 25
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 25
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 24
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 24
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 23
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 23
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 22
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 22
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 21
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 21
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 20
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 20
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 19
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 19
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 18
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 18
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 17
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 17
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 16
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 16
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 28
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 28
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 15
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 15
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 14
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 14
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 13
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 13
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 11
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 11
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 10
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 10
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 9
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 9
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 7
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 7
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 6
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 6
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 5
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 5
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 3
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 3
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 12
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 12
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 47
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 47
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 46
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 46
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 45
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 45
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 43
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 43
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 42
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 42
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 41
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 41
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 40
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 40
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 39
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 39
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 38
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 38
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 37
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 37
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 36
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 36
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 35
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 35
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 34
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 34
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 33
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 33
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 32
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 32
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 44
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 44
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 63
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 63
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 62
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 62
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 61
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 61
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 59
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 59
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 58
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 58
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 57
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 57
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 56
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 56
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 55
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 55
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 54
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 54
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 53
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 53
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 52
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 52
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 51
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 51
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 50
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 50
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 49
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 49
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 48
                        i32.add
                        local.tee 24
                        local.get 23
                        i32.const 48
                        i32.add
                        i32.load8_u
                        local.get 24
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 0
                        i32.const 60
                        i32.add
                        local.tee 0
                        local.get 23
                        i32.const 60
                        i32.add
                        i32.load8_u
                        local.get 0
                        i32.load8_u
                        i32.xor
                        i32.store8
                        local.get 22
                        i32.const 64
                        i32.add
                        local.set 22
                        local.get 1
                        i64.const 64
                        i64.add
                        local.set 1
                        local.get 20
                        i64.const 2
                        i64.add
                        local.tee 20
                        i64.const 0
                        i64.ne
                        br_if 0 (;@10;)
                      end
                    end
                    block  ;; label = @9
                      local.get 17
                      i64.eqz
                      br_if 0 (;@9;)
                      local.get 8
                      i32.const 736
                      i32.add
                      local.get 1
                      i32.wrap_i64
                      local.tee 23
                      i32.add
                      local.tee 0
                      local.get 8
                      i32.const 1536
                      i32.add
                      local.get 23
                      i32.add
                      local.tee 23
                      i32.load8_u offset=16
                      local.get 0
                      i32.load8_u offset=16
                      i32.xor
                      i32.store8 offset=16
                      local.get 0
                      local.get 23
                      i32.load8_u offset=8
                      local.get 0
                      i32.load8_u offset=8
                      i32.xor
                      i32.store8 offset=8
                      local.get 0
                      local.get 23
                      i32.load8_u offset=4
                      local.get 0
                      i32.load8_u offset=4
                      i32.xor
                      i32.store8 offset=4
                      local.get 0
                      local.get 23
                      i32.load8_u offset=2
                      local.get 0
                      i32.load8_u offset=2
                      i32.xor
                      i32.store8 offset=2
                      local.get 0
                      local.get 23
                      i32.load8_u offset=1
                      local.get 0
                      i32.load8_u offset=1
                      i32.xor
                      i32.store8 offset=1
                      local.get 0
                      local.get 23
                      i32.load8_u
                      local.get 0
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 31
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 31
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 30
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 30
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 29
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 29
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 27
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 27
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 26
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 26
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 25
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 25
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 24
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 24
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 23
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 23
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 22
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 22
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 21
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 21
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 20
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 20
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 19
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 19
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 18
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 18
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 17
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 17
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 28
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 28
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 15
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 15
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 14
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 14
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 13
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 13
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 11
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 11
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 10
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 10
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 9
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 9
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 7
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 7
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 6
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 6
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 5
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 5
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 3
                      i32.add
                      local.tee 22
                      local.get 23
                      i32.const 3
                      i32.add
                      i32.load8_u
                      local.get 22
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 0
                      i32.const 12
                      i32.add
                      local.tee 0
                      local.get 23
                      i32.const 12
                      i32.add
                      i32.load8_u
                      local.get 0
                      i32.load8_u
                      i32.xor
                      i32.store8
                    end
                    local.get 11
                    local.get 13
                    i64.eq
                    br_if 2 (;@6;)
                    local.get 13
                    local.set 21
                    local.get 13
                    local.set 20
                    local.get 12
                    i64.eqz
                    br_if 1 (;@7;)
                  end
                  local.get 15
                  local.get 21
                  i64.add
                  local.set 1
                  local.get 8
                  i32.const 736
                  i32.add
                  local.get 21
                  i32.wrap_i64
                  local.tee 23
                  i32.add
                  local.set 0
                  local.get 8
                  i32.const 1536
                  i32.add
                  local.get 23
                  i32.add
                  local.set 23
                  loop  ;; label = @8
                    local.get 0
                    local.get 23
                    i32.load8_u offset=4
                    local.get 0
                    i32.load8_u offset=4
                    i32.xor
                    i32.store8 offset=4
                    local.get 0
                    local.get 23
                    i32.load8_u offset=2
                    local.get 0
                    i32.load8_u offset=2
                    i32.xor
                    i32.store8 offset=2
                    local.get 0
                    local.get 23
                    i32.load8_u offset=1
                    local.get 0
                    i32.load8_u offset=1
                    i32.xor
                    i32.store8 offset=1
                    local.get 0
                    local.get 23
                    i32.load8_u
                    local.get 0
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 0
                    i32.const 7
                    i32.add
                    local.tee 22
                    local.get 23
                    i32.const 7
                    i32.add
                    i32.load8_u
                    local.get 22
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 0
                    i32.const 6
                    i32.add
                    local.tee 22
                    local.get 23
                    i32.const 6
                    i32.add
                    i32.load8_u
                    local.get 22
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 0
                    i32.const 5
                    i32.add
                    local.tee 22
                    local.get 23
                    i32.const 5
                    i32.add
                    i32.load8_u
                    local.get 22
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 0
                    i32.const 3
                    i32.add
                    local.tee 22
                    local.get 23
                    i32.const 3
                    i32.add
                    i32.load8_u
                    local.get 22
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 0
                    i32.const 8
                    i32.add
                    local.set 0
                    local.get 23
                    i32.const 8
                    i32.add
                    local.set 23
                    local.get 1
                    i64.const 8
                    i64.add
                    local.tee 1
                    i64.const 0
                    i64.ne
                    br_if 0 (;@8;)
                  end
                  local.get 14
                  local.set 20
                  local.get 11
                  local.get 14
                  i64.eq
                  br_if 1 (;@6;)
                end
                local.get 11
                local.get 20
                i64.sub
                local.set 1
                local.get 8
                i32.const 736
                i32.add
                local.get 20
                i32.wrap_i64
                local.tee 23
                i32.add
                local.set 0
                local.get 8
                i32.const 1536
                i32.add
                local.get 23
                i32.add
                local.set 23
                loop  ;; label = @7
                  local.get 0
                  local.get 23
                  i32.load8_u
                  local.get 0
                  i32.load8_u
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 1
                  i32.add
                  local.set 0
                  local.get 23
                  i32.const 1
                  i32.add
                  local.set 23
                  local.get 1
                  i64.const -1
                  i64.add
                  local.tee 1
                  i64.const 0
                  i64.ne
                  br_if 0 (;@7;)
                end
              end
              local.get 19
              i32.const 1
              i32.add
              local.tee 19
              local.get 4
              i32.ne
              br_if 0 (;@5;)
            end
          end
          local.get 10
          i32.const 1
          i32.add
          local.set 10
          local.get 5
          local.get 8
          i32.const 736
          i32.add
          local.get 6
          local.get 7
          i64.load
          local.tee 1
          local.get 6
          local.get 1
          i64.lt_u
          select
          local.tee 1
          i32.wrap_i64
          local.tee 0
          call $memcpy
          local.get 0
          i32.add
          local.set 5
          local.get 6
          local.get 1
          i64.sub
          local.tee 6
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
        end
        i32.const 0
        i32.load
        local.get 8
        i32.load offset=1612
        i32.ne
        br_if 1 (;@1;)
        local.get 8
        i32.const 1616
        i32.add
        global.set $__stack_pointer
        return
      end
      call $abort
      unreachable
    end
    call $__stack_chk_fail
    unreachable)
  (func $pw_check (type 16) (param i32 i64 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 1136
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    i32.const 0
    i32.load
    i32.store offset=1132
    local.get 4
    i32.const 24
    i32.add
    i32.const 48
    i32.add
    i64.const 0
    i64.store
    local.get 4
    i32.const 24
    i32.add
    i32.const 40
    i32.add
    i64.const 0
    i64.store
    local.get 4
    i32.const 24
    i32.add
    i32.const 32
    i32.add
    i64.const 0
    i64.store
    local.get 4
    i32.const 24
    i32.add
    i32.const 24
    i32.add
    i64.const 0
    i64.store
    local.get 4
    i32.const 24
    i32.add
    i32.const 16
    i32.add
    i64.const 0
    i64.store
    local.get 4
    i32.const 32
    i32.add
    i64.const 0
    i64.store
    local.get 4
    i64.const 0
    i64.store offset=24
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          i32.const 0
          i32.load8_u offset=1488
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          i32.const 96
          i32.add
          i32.const 48
          i32.add
          i64.const 0
          i64.store
          local.get 4
          i32.const 96
          i32.add
          i32.const 40
          i32.add
          i64.const 0
          i64.store
          local.get 4
          i32.const 96
          i32.add
          i32.const 32
          i32.add
          i64.const 0
          i64.store
          local.get 4
          i32.const 96
          i32.add
          i32.const 24
          i32.add
          i64.const 0
          i64.store
          local.get 4
          i32.const 96
          i32.add
          i32.const 16
          i32.add
          i64.const 0
          i64.store
          local.get 4
          i64.const 0
          i64.store offset=104
          local.get 4
          i64.const 0
          i64.store offset=96
          br 1 (;@2;)
        end
        i32.const 1
        local.set 5
        block  ;; label = @3
          local.get 4
          i32.const 20
          i32.add
          local.get 4
          i32.const 96
          i32.add
          i32.const 1024
          local.get 4
          i32.const 16
          i32.add
          call $read_region_data
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=20
          local.tee 5
          br_if 0 (;@3;)
          local.get 4
          i32.const 16
          i32.store offset=12
          i32.const 2
          local.set 5
          local.get 4
          i32.const 96
          i32.add
          i32.const 0
          i32.const 0
          local.get 4
          i32.const 80
          i32.add
          local.get 4
          i32.const 12
          i32.add
          call $sgx_unseal_data
          br_if 0 (;@3;)
          local.get 4
          i32.load offset=12
          i32.const 16
          i32.ne
          br_if 0 (;@3;)
          i32.const 0
          local.set 5
          i32.const 0
          local.get 4
          i64.load offset=88
          i64.store offset=1512
          i32.const 0
          local.get 4
          i64.load offset=80
          i64.store offset=1504
          i32.const 0
          i32.const 1
          i32.store8 offset=1488
        end
        local.get 5
        br_if 1 (;@1;)
        i32.const 0
        i32.load8_u offset=1488
        local.set 5
        local.get 4
        i32.const 144
        i32.add
        i64.const 0
        i64.store
        local.get 4
        i32.const 136
        i32.add
        i64.const 0
        i64.store
        local.get 4
        i32.const 128
        i32.add
        i64.const 0
        i64.store
        local.get 4
        i32.const 120
        i32.add
        i64.const 0
        i64.store
        local.get 4
        i32.const 112
        i32.add
        i64.const 0
        i64.store
        local.get 4
        i64.const 0
        i64.store offset=104
        local.get 4
        i64.const 0
        i64.store offset=96
        local.get 5
        br_if 0 (;@2;)
        i32.const 1076
        i32.const 179
        i32.const 1059
        i32.const 1024
        call $__assert
      end
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i32.const 84
          i32.ne
          br_if 0 (;@3;)
          i32.const 1504
          local.get 2
          i32.const 28
          i32.add
          i32.const 56
          local.get 4
          i32.const 96
          i32.add
          local.get 2
          i32.const 12
          i32.const 0
          i32.const 0
          local.get 2
          i32.const 12
          i32.add
          call $sgx_rijndael128GCM_decrypt
          br_if 0 (;@3;)
          local.get 4
          i32.const 24
          i32.add
          i32.const 16
          i32.add
          local.get 4
          i32.const 96
          i32.add
          i32.const 16
          i32.add
          i64.load
          i64.store
          local.get 4
          i32.const 24
          i32.add
          i32.const 32
          i32.add
          local.get 4
          i32.const 96
          i32.add
          i32.const 32
          i32.add
          i64.load
          i64.store
          local.get 4
          i32.const 24
          i32.add
          i32.const 40
          i32.add
          local.get 4
          i32.const 96
          i32.add
          i32.const 40
          i32.add
          i64.load
          i64.store
          local.get 4
          i32.const 24
          i32.add
          i32.const 48
          i32.add
          local.get 4
          i32.const 96
          i32.add
          i32.const 48
          i32.add
          i64.load
          i64.store
          local.get 4
          local.get 4
          i64.load offset=104
          i64.store offset=32
          local.get 4
          local.get 4
          i64.load offset=120
          i64.store offset=48
          local.get 4
          local.get 4
          i32.load offset=100
          local.tee 5
          i32.const 24
          i32.shl
          local.get 5
          i32.const 8
          i32.shl
          i32.const 16711680
          i32.and
          i32.or
          local.get 5
          i32.const 8
          i32.shr_u
          i32.const 65280
          i32.and
          local.get 5
          i32.const 24
          i32.shr_u
          i32.or
          i32.or
          local.tee 2
          i32.store offset=28
          local.get 4
          local.get 4
          i32.load offset=96
          local.tee 5
          i32.const 24
          i32.shl
          local.get 5
          i32.const 8
          i32.shl
          i32.const 16711680
          i32.and
          i32.or
          local.get 5
          i32.const 8
          i32.shr_u
          i32.const 65280
          i32.and
          local.get 5
          i32.const 24
          i32.shr_u
          i32.or
          i32.or
          local.tee 5
          i32.store offset=24
          local.get 5
          i32.const 1
          i32.eq
          br_if 1 (;@2;)
        end
        i32.const 2
        local.set 5
        br 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        br_if 0 (;@2;)
        i32.const 2
        local.set 5
        br 1 (;@1;)
      end
      local.get 4
      i32.const 24
      i32.add
      i32.const 24
      i32.add
      local.set 5
      local.get 0
      local.get 1
      i64.const 4294967295
      i64.and
      local.get 4
      i32.const 24
      i32.add
      i32.const 8
      i32.add
      i64.const 16
      local.get 2
      local.get 4
      i32.const 96
      i32.add
      i64.const 32
      i32.const 1192
      call $cf_pbkdf2_hmac
      i32.const 0
      local.set 3
      i64.const -32
      local.set 1
      local.get 4
      i32.const 96
      i32.add
      local.set 2
      loop  ;; label = @2
        local.get 5
        i32.load8_u
        local.set 0
        local.get 2
        i32.load8_u
        local.set 6
        local.get 5
        i32.const 1
        i32.add
        i32.load8_u
        local.set 7
        local.get 2
        i32.const 1
        i32.add
        i32.load8_u
        local.set 8
        local.get 5
        i32.const 2
        i32.add
        i32.load8_u
        local.set 9
        local.get 2
        i32.const 2
        i32.add
        i32.load8_u
        local.set 10
        local.get 5
        i32.const 3
        i32.add
        i32.load8_u
        local.get 2
        i32.const 3
        i32.add
        i32.load8_u
        i32.xor
        local.get 10
        local.get 9
        i32.xor
        local.get 8
        local.get 7
        i32.xor
        local.get 6
        local.get 0
        i32.xor
        local.get 3
        i32.or
        i32.or
        i32.or
        i32.or
        local.set 3
        local.get 2
        i32.const 4
        i32.add
        local.set 2
        local.get 5
        i32.const 4
        i32.add
        local.set 5
        local.get 1
        i64.const 4
        i64.add
        local.tee 1
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
      end
      local.get 4
      i32.const 32
      i32.add
      i64.const 0
      i64.store
      local.get 4
      i32.const 40
      i32.add
      i64.const 0
      i64.store
      local.get 4
      i32.const 48
      i32.add
      i64.const 0
      i64.store
      local.get 4
      i32.const 56
      i32.add
      i64.const 0
      i64.store
      local.get 4
      i32.const 64
      i32.add
      i64.const 0
      i64.store
      local.get 4
      i32.const 72
      i32.add
      i64.const 0
      i64.store
      local.get 4
      i64.const 0
      i64.store offset=24
      i32.const 3
      i32.const 0
      local.get 3
      i32.const 255
      i32.and
      select
      local.set 5
      local.get 4
      i32.load8_u offset=24
      drop
    end
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 4
      i32.load offset=1132
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 4
    i32.const 1136
    i32.add
    global.set $__stack_pointer
    local.get 5)
  (func $cf_blockwise_accumulate (type 17) (param i32 i32 i64 i32 i64 i32 i32)
    local.get 0
    local.get 1
    local.get 2
    local.get 3
    local.get 4
    local.get 5
    local.get 5
    local.get 6
    call $cf_blockwise_accumulate_final)
  (func $cf_blockwise_accumulate_final (type 18) (param i32 i32 i64 i32 i64 i32 i32 i32)
    (local i64 i64 i32)
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      i64.load
      local.tee 8
      local.get 2
      i64.ge_u
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 3
        br_if 0 (;@2;)
        local.get 4
        i64.eqz
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 5
      i32.eqz
      br_if 0 (;@1;)
      local.get 7
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 8
        i64.eqz
        br_if 0 (;@2;)
        local.get 4
        i64.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 8
        i32.wrap_i64
        i32.add
        local.get 3
        local.get 2
        local.get 8
        i64.sub
        local.tee 8
        local.get 4
        local.get 8
        local.get 4
        i64.lt_u
        select
        local.tee 9
        i32.wrap_i64
        local.tee 10
        call $memcpy
        drop
        local.get 1
        local.get 1
        i64.load
        local.get 9
        i64.add
        local.tee 8
        i64.store
        local.get 4
        local.get 9
        i64.sub
        local.set 4
        local.get 3
        local.get 10
        i32.add
        local.set 3
        local.get 8
        local.get 2
        i64.ne
        br_if 0 (;@2;)
        local.get 7
        local.get 0
        local.get 6
        local.get 5
        local.get 4
        i64.eqz
        select
        call_indirect (type 0)
        i64.const 0
        local.set 8
        local.get 1
        i64.const 0
        i64.store
      end
      block  ;; label = @2
        local.get 4
        local.get 2
        i64.lt_u
        br_if 0 (;@2;)
        local.get 8
        i64.const 0
        i64.ne
        br_if 1 (;@1;)
        local.get 4
        local.get 2
        i64.sub
        local.set 4
        local.get 2
        i32.wrap_i64
        local.set 10
        loop  ;; label = @3
          local.get 7
          local.get 3
          local.get 6
          local.get 5
          local.get 4
          i64.eqz
          select
          call_indirect (type 0)
          block  ;; label = @4
            local.get 4
            local.get 2
            i64.ge_u
            br_if 0 (;@4;)
            local.get 3
            local.get 10
            i32.add
            local.set 3
            br 2 (;@2;)
          end
          local.get 3
          local.get 10
          i32.add
          local.set 3
          local.get 4
          local.get 2
          i64.sub
          local.set 4
          local.get 1
          i64.load
          i64.eqz
          br_if 0 (;@3;)
          br 2 (;@1;)
        end
      end
      block  ;; label = @2
        local.get 4
        i64.eqz
        br_if 0 (;@2;)
        local.get 1
        i64.load
        local.set 8
        loop  ;; label = @3
          local.get 0
          local.get 8
          i32.wrap_i64
          i32.add
          local.get 3
          local.get 2
          local.get 8
          i64.sub
          local.tee 8
          local.get 4
          local.get 8
          local.get 4
          i64.lt_u
          select
          local.tee 9
          i32.wrap_i64
          local.tee 5
          call $memcpy
          drop
          local.get 1
          local.get 9
          local.get 1
          i64.load
          i64.add
          local.tee 8
          i64.store
          local.get 8
          local.get 2
          i64.ge_u
          br_if 2 (;@1;)
          local.get 3
          local.get 5
          i32.add
          local.set 3
          local.get 4
          local.get 9
          i64.sub
          local.tee 4
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
        end
      end
      return
    end
    call $abort
    unreachable)
  (func $cf_blockwise_xor (type 19) (param i32 i32 i64 i32 i32 i64 i32 i32)
    (local i64 i64 i32 i64 i64 i64 i32 i64 i64 i64 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      i64.load
      local.tee 8
      local.get 2
      i64.ge_u
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 3
        br_if 0 (;@2;)
        local.get 5
        i64.eqz
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 6
      i32.eqz
      br_if 0 (;@1;)
      local.get 7
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 5
        i64.eqz
        br_if 0 (;@2;)
        local.get 2
        i64.const 1
        i64.add
        local.set 9
        local.get 0
        local.get 2
        i32.wrap_i64
        i32.add
        local.set 10
        loop  ;; label = @3
          block  ;; label = @4
            local.get 8
            i64.const 0
            i64.ne
            br_if 0 (;@4;)
            local.get 7
            local.get 0
            local.get 6
            call_indirect (type 0)
            local.get 1
            local.get 2
            i64.store
            local.get 2
            local.set 8
          end
          block  ;; label = @4
            local.get 8
            local.get 5
            local.get 8
            local.get 5
            i64.lt_u
            select
            local.tee 11
            i64.eqz
            br_if 0 (;@4;)
            local.get 2
            local.get 8
            i64.sub
            local.set 12
            i64.const 0
            local.set 13
            block  ;; label = @5
              block  ;; label = @6
                local.get 11
                i64.const 8
                i64.lt_u
                br_if 0 (;@6;)
                local.get 4
                local.get 3
                local.get 11
                i32.wrap_i64
                local.tee 14
                i32.add
                i32.lt_u
                local.get 3
                local.get 4
                local.get 14
                i32.add
                local.tee 14
                i32.lt_u
                i32.and
                br_if 0 (;@6;)
                local.get 4
                local.get 0
                local.get 11
                local.get 8
                i64.sub
                local.get 2
                i64.add
                i32.wrap_i64
                i32.add
                i32.lt_u
                local.get 0
                local.get 12
                i32.wrap_i64
                i32.add
                local.get 14
                i32.lt_u
                i32.and
                br_if 0 (;@6;)
                i64.const 0
                local.set 13
                block  ;; label = @7
                  local.get 11
                  i64.const 32
                  i64.lt_u
                  br_if 0 (;@7;)
                  local.get 11
                  i64.const -32
                  i64.and
                  local.tee 13
                  i64.const -32
                  i64.add
                  local.tee 15
                  i64.const 5
                  i64.shr_u
                  i64.const 1
                  i64.add
                  local.tee 16
                  i64.const 1
                  i64.and
                  local.set 17
                  block  ;; label = @8
                    block  ;; label = @9
                      local.get 15
                      i64.eqz
                      i32.eqz
                      br_if 0 (;@9;)
                      i64.const 0
                      local.set 15
                      br 1 (;@8;)
                    end
                    local.get 10
                    local.get 8
                    i32.wrap_i64
                    i32.sub
                    local.set 18
                    i64.const 0
                    local.set 15
                    i64.const 0
                    local.get 16
                    i64.const 1152921504606846974
                    i64.and
                    i64.sub
                    local.set 16
                    i32.const 0
                    local.set 19
                    loop  ;; label = @9
                      local.get 4
                      local.get 19
                      i32.add
                      local.tee 14
                      local.get 18
                      local.get 19
                      i32.add
                      local.tee 20
                      i32.load8_u offset=8
                      local.get 3
                      local.get 19
                      i32.add
                      local.tee 21
                      i32.load8_u offset=8
                      i32.xor
                      i32.store8 offset=8
                      local.get 14
                      local.get 20
                      i32.load8_u offset=4
                      local.get 21
                      i32.load8_u offset=4
                      i32.xor
                      i32.store8 offset=4
                      local.get 14
                      local.get 20
                      i32.load8_u offset=2
                      local.get 21
                      i32.load8_u offset=2
                      i32.xor
                      i32.store8 offset=2
                      local.get 14
                      local.get 20
                      i32.load8_u offset=1
                      local.get 21
                      i32.load8_u offset=1
                      i32.xor
                      i32.store8 offset=1
                      local.get 14
                      local.get 20
                      i32.load8_u
                      local.get 21
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 31
                      i32.add
                      local.get 20
                      i32.const 31
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 31
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 30
                      i32.add
                      local.get 20
                      i32.const 30
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 30
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 29
                      i32.add
                      local.get 20
                      i32.const 29
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 29
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 28
                      i32.add
                      local.get 20
                      i32.const 28
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 28
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 27
                      i32.add
                      local.get 20
                      i32.const 27
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 27
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 26
                      i32.add
                      local.get 20
                      i32.const 26
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 26
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 25
                      i32.add
                      local.get 20
                      i32.const 25
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 25
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 24
                      i32.add
                      local.get 20
                      i32.const 24
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 24
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 23
                      i32.add
                      local.get 20
                      i32.const 23
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 23
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 22
                      i32.add
                      local.get 20
                      i32.const 22
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 22
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 21
                      i32.add
                      local.get 20
                      i32.const 21
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 21
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 20
                      i32.add
                      local.get 20
                      i32.const 20
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 20
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 19
                      i32.add
                      local.get 20
                      i32.const 19
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 19
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 18
                      i32.add
                      local.get 20
                      i32.const 18
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 18
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 17
                      i32.add
                      local.get 20
                      i32.const 17
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 17
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 16
                      i32.add
                      local.get 20
                      i32.const 16
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 16
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 15
                      i32.add
                      local.get 20
                      i32.const 15
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 15
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 14
                      i32.add
                      local.get 20
                      i32.const 14
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 14
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 13
                      i32.add
                      local.get 20
                      i32.const 13
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 13
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 12
                      i32.add
                      local.get 20
                      i32.const 12
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 12
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 11
                      i32.add
                      local.get 20
                      i32.const 11
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 11
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 10
                      i32.add
                      local.get 20
                      i32.const 10
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 10
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 9
                      i32.add
                      local.get 20
                      i32.const 9
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 9
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 7
                      i32.add
                      local.get 20
                      i32.const 7
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 7
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 6
                      i32.add
                      local.get 20
                      i32.const 6
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 6
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 5
                      i32.add
                      local.get 20
                      i32.const 5
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 5
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 3
                      i32.add
                      local.get 20
                      i32.const 3
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 3
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 63
                      i32.add
                      local.get 20
                      i32.const 63
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 63
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 62
                      i32.add
                      local.get 20
                      i32.const 62
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 62
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 61
                      i32.add
                      local.get 20
                      i32.const 61
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 61
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 60
                      i32.add
                      local.get 20
                      i32.const 60
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 60
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 59
                      i32.add
                      local.get 20
                      i32.const 59
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 59
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 58
                      i32.add
                      local.get 20
                      i32.const 58
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 58
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 57
                      i32.add
                      local.get 20
                      i32.const 57
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 57
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 56
                      i32.add
                      local.get 20
                      i32.const 56
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 56
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 55
                      i32.add
                      local.get 20
                      i32.const 55
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 55
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 54
                      i32.add
                      local.get 20
                      i32.const 54
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 54
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 53
                      i32.add
                      local.get 20
                      i32.const 53
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 53
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 52
                      i32.add
                      local.get 20
                      i32.const 52
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 52
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 51
                      i32.add
                      local.get 20
                      i32.const 51
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 51
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 50
                      i32.add
                      local.get 20
                      i32.const 50
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 50
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 49
                      i32.add
                      local.get 20
                      i32.const 49
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 49
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 48
                      i32.add
                      local.get 20
                      i32.const 48
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 48
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 47
                      i32.add
                      local.get 20
                      i32.const 47
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 47
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 46
                      i32.add
                      local.get 20
                      i32.const 46
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 46
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 45
                      i32.add
                      local.get 20
                      i32.const 45
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 45
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 44
                      i32.add
                      local.get 20
                      i32.const 44
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 44
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 43
                      i32.add
                      local.get 20
                      i32.const 43
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 43
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 42
                      i32.add
                      local.get 20
                      i32.const 42
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 42
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 41
                      i32.add
                      local.get 20
                      i32.const 41
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 41
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 40
                      i32.add
                      local.get 20
                      i32.const 40
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 40
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 39
                      i32.add
                      local.get 20
                      i32.const 39
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 39
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 38
                      i32.add
                      local.get 20
                      i32.const 38
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 38
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 37
                      i32.add
                      local.get 20
                      i32.const 37
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 37
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 36
                      i32.add
                      local.get 20
                      i32.const 36
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 36
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 35
                      i32.add
                      local.get 20
                      i32.const 35
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 35
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 34
                      i32.add
                      local.get 20
                      i32.const 34
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 34
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 33
                      i32.add
                      local.get 20
                      i32.const 33
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 33
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 14
                      i32.const 32
                      i32.add
                      local.get 20
                      i32.const 32
                      i32.add
                      i32.load8_u
                      local.get 21
                      i32.const 32
                      i32.add
                      i32.load8_u
                      i32.xor
                      i32.store8
                      local.get 19
                      i32.const 64
                      i32.add
                      local.set 19
                      local.get 15
                      i64.const 64
                      i64.add
                      local.set 15
                      local.get 16
                      i64.const 2
                      i64.add
                      local.tee 16
                      i64.const 0
                      i64.ne
                      br_if 0 (;@9;)
                    end
                  end
                  block  ;; label = @8
                    local.get 17
                    i64.eqz
                    br_if 0 (;@8;)
                    local.get 4
                    local.get 15
                    i32.wrap_i64
                    local.tee 21
                    i32.add
                    local.tee 14
                    local.get 0
                    local.get 12
                    local.get 15
                    i64.add
                    i32.wrap_i64
                    i32.add
                    local.tee 20
                    i32.load8_u offset=16
                    local.get 3
                    local.get 21
                    i32.add
                    local.tee 21
                    i32.load8_u offset=16
                    i32.xor
                    i32.store8 offset=16
                    local.get 14
                    local.get 20
                    i32.load8_u offset=8
                    local.get 21
                    i32.load8_u offset=8
                    i32.xor
                    i32.store8 offset=8
                    local.get 14
                    local.get 20
                    i32.load8_u offset=4
                    local.get 21
                    i32.load8_u offset=4
                    i32.xor
                    i32.store8 offset=4
                    local.get 14
                    local.get 20
                    i32.load8_u offset=2
                    local.get 21
                    i32.load8_u offset=2
                    i32.xor
                    i32.store8 offset=2
                    local.get 14
                    local.get 20
                    i32.load8_u offset=1
                    local.get 21
                    i32.load8_u offset=1
                    i32.xor
                    i32.store8 offset=1
                    local.get 14
                    local.get 20
                    i32.load8_u
                    local.get 21
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 31
                    i32.add
                    local.get 20
                    i32.const 31
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 31
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 30
                    i32.add
                    local.get 20
                    i32.const 30
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 30
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 29
                    i32.add
                    local.get 20
                    i32.const 29
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 29
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 28
                    i32.add
                    local.get 20
                    i32.const 28
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 28
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 27
                    i32.add
                    local.get 20
                    i32.const 27
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 27
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 26
                    i32.add
                    local.get 20
                    i32.const 26
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 26
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 25
                    i32.add
                    local.get 20
                    i32.const 25
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 25
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 24
                    i32.add
                    local.get 20
                    i32.const 24
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 24
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 23
                    i32.add
                    local.get 20
                    i32.const 23
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 23
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 22
                    i32.add
                    local.get 20
                    i32.const 22
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 22
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 21
                    i32.add
                    local.get 20
                    i32.const 21
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 21
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 20
                    i32.add
                    local.get 20
                    i32.const 20
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 20
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 19
                    i32.add
                    local.get 20
                    i32.const 19
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 19
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 18
                    i32.add
                    local.get 20
                    i32.const 18
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 18
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 17
                    i32.add
                    local.get 20
                    i32.const 17
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 17
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 15
                    i32.add
                    local.get 20
                    i32.const 15
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 15
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 14
                    i32.add
                    local.get 20
                    i32.const 14
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 14
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 13
                    i32.add
                    local.get 20
                    i32.const 13
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 13
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 12
                    i32.add
                    local.get 20
                    i32.const 12
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 12
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 11
                    i32.add
                    local.get 20
                    i32.const 11
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 11
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 10
                    i32.add
                    local.get 20
                    i32.const 10
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 10
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 9
                    i32.add
                    local.get 20
                    i32.const 9
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 9
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 7
                    i32.add
                    local.get 20
                    i32.const 7
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 7
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 6
                    i32.add
                    local.get 20
                    i32.const 6
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 6
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 5
                    i32.add
                    local.get 20
                    i32.const 5
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 5
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                    local.get 14
                    i32.const 3
                    i32.add
                    local.get 20
                    i32.const 3
                    i32.add
                    i32.load8_u
                    local.get 21
                    i32.const 3
                    i32.add
                    i32.load8_u
                    i32.xor
                    i32.store8
                  end
                  local.get 11
                  local.get 13
                  i64.eq
                  br_if 2 (;@5;)
                  local.get 11
                  i64.const 24
                  i64.and
                  i64.eqz
                  br_if 1 (;@6;)
                end
                local.get 3
                local.get 13
                i32.wrap_i64
                local.tee 20
                i32.add
                local.set 14
                local.get 4
                local.get 20
                i32.add
                local.set 20
                local.get 0
                local.get 2
                local.get 13
                i64.add
                local.get 8
                i64.sub
                i32.wrap_i64
                i32.add
                local.set 21
                local.get 13
                local.get 5
                local.get 8
                local.get 5
                local.get 8
                i64.lt_u
                select
                local.tee 17
                i64.const -8
                i64.and
                local.tee 16
                i64.sub
                local.set 15
                loop  ;; label = @7
                  local.get 21
                  i32.const 3
                  i32.add
                  i32.load8_u
                  local.set 19
                  local.get 14
                  i32.const 3
                  i32.add
                  i32.load8_u
                  local.set 18
                  local.get 21
                  i32.const 5
                  i32.add
                  i32.load8_u
                  local.set 22
                  local.get 14
                  i32.const 5
                  i32.add
                  i32.load8_u
                  local.set 23
                  local.get 21
                  i32.const 6
                  i32.add
                  i32.load8_u
                  local.set 24
                  local.get 14
                  i32.const 6
                  i32.add
                  i32.load8_u
                  local.set 25
                  local.get 21
                  i32.const 7
                  i32.add
                  i32.load8_u
                  local.set 26
                  local.get 14
                  i32.const 7
                  i32.add
                  i32.load8_u
                  local.set 27
                  local.get 21
                  i32.load8_u
                  local.set 28
                  local.get 14
                  i32.load8_u
                  local.set 29
                  local.get 21
                  i32.load8_u offset=1
                  local.set 30
                  local.get 14
                  i32.load8_u offset=1
                  local.set 31
                  local.get 21
                  i32.load8_u offset=2
                  local.set 32
                  local.get 14
                  i32.load8_u offset=2
                  local.set 33
                  local.get 20
                  local.get 21
                  i32.load8_u offset=4
                  local.get 14
                  i32.load8_u offset=4
                  i32.xor
                  i32.store8 offset=4
                  local.get 20
                  local.get 32
                  local.get 33
                  i32.xor
                  i32.store8 offset=2
                  local.get 20
                  local.get 30
                  local.get 31
                  i32.xor
                  i32.store8 offset=1
                  local.get 20
                  local.get 28
                  local.get 29
                  i32.xor
                  i32.store8
                  local.get 20
                  i32.const 7
                  i32.add
                  local.get 26
                  local.get 27
                  i32.xor
                  i32.store8
                  local.get 20
                  i32.const 6
                  i32.add
                  local.get 24
                  local.get 25
                  i32.xor
                  i32.store8
                  local.get 20
                  i32.const 5
                  i32.add
                  local.get 22
                  local.get 23
                  i32.xor
                  i32.store8
                  local.get 20
                  i32.const 3
                  i32.add
                  local.get 19
                  local.get 18
                  i32.xor
                  i32.store8
                  local.get 14
                  i32.const 8
                  i32.add
                  local.set 14
                  local.get 21
                  i32.const 8
                  i32.add
                  local.set 21
                  local.get 20
                  i32.const 8
                  i32.add
                  local.set 20
                  local.get 15
                  i64.const 8
                  i64.add
                  local.tee 15
                  i64.const 0
                  i64.ne
                  br_if 0 (;@7;)
                end
                local.get 16
                local.set 13
                local.get 17
                local.get 16
                i64.eq
                br_if 1 (;@5;)
              end
              local.get 13
              i64.const 1
              i64.or
              local.set 15
              block  ;; label = @6
                local.get 11
                i64.const 1
                i64.and
                i64.eqz
                br_if 0 (;@6;)
                local.get 4
                local.get 13
                i32.wrap_i64
                local.tee 14
                i32.add
                local.get 0
                local.get 12
                local.get 13
                i64.add
                i32.wrap_i64
                i32.add
                i32.load8_u
                local.get 3
                local.get 14
                i32.add
                i32.load8_u
                i32.xor
                i32.store8
                local.get 15
                local.set 13
              end
              local.get 11
              local.get 15
              i64.eq
              br_if 0 (;@5;)
              local.get 11
              local.get 13
              i64.sub
              local.set 15
              local.get 3
              local.get 13
              i32.wrap_i64
              local.tee 20
              i32.add
              local.set 14
              local.get 4
              local.get 20
              i32.add
              local.set 20
              local.get 0
              local.get 2
              local.get 13
              i64.add
              local.get 8
              i64.sub
              i32.wrap_i64
              i32.add
              local.set 21
              local.get 0
              local.get 9
              local.get 13
              i64.add
              local.get 8
              i64.sub
              i32.wrap_i64
              i32.add
              local.set 19
              loop  ;; label = @6
                local.get 20
                local.get 21
                i32.load8_u
                local.get 14
                i32.load8_u
                i32.xor
                i32.store8
                local.get 20
                i32.const 1
                i32.add
                local.get 19
                i32.load8_u
                local.get 14
                i32.const 1
                i32.add
                i32.load8_u
                i32.xor
                i32.store8
                local.get 21
                i32.const 2
                i32.add
                local.set 21
                local.get 14
                i32.const 2
                i32.add
                local.set 14
                local.get 19
                i32.const 2
                i32.add
                local.set 19
                local.get 20
                i32.const 2
                i32.add
                local.set 20
                local.get 15
                i64.const -2
                i64.add
                local.tee 15
                i64.const 0
                i64.ne
                br_if 0 (;@6;)
              end
            end
            local.get 1
            i64.load
            local.set 8
          end
          local.get 1
          local.get 8
          local.get 11
          i64.sub
          local.tee 8
          i64.store
          local.get 3
          local.get 11
          i32.wrap_i64
          local.tee 14
          i32.add
          local.set 3
          local.get 4
          local.get 14
          i32.add
          local.set 4
          local.get 5
          local.get 11
          i64.sub
          local.tee 5
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
        end
      end
      return
    end
    call $abort
    unreachable)
  (func $cf_blockwise_acc_byte (type 17) (param i32 i32 i64 i32 i64 i32 i32)
    (local i64 i32 i64 i32 i32)
    block  ;; label = @1
      local.get 4
      i64.eqz
      br_if 0 (;@1;)
      local.get 1
      i64.load
      local.set 7
      i32.const 0
      local.set 8
      loop  ;; label = @2
        local.get 4
        local.get 2
        local.get 7
        i64.sub
        local.tee 9
        local.get 4
        local.get 9
        i64.lt_u
        select
        local.set 9
        block  ;; label = @3
          local.get 8
          br_if 0 (;@3;)
          local.get 0
          local.get 7
          i32.wrap_i64
          i32.add
          local.get 3
          local.get 9
          i32.wrap_i64
          call $memset
          drop
        end
        i32.const 1
        local.get 8
        local.get 9
        local.get 2
        i64.eq
        select
        local.set 10
        local.get 7
        i64.eqz
        local.set 11
        block  ;; label = @3
          block  ;; label = @4
            local.get 9
            local.get 7
            i64.add
            local.get 2
            i64.ne
            br_if 0 (;@4;)
            local.get 6
            local.get 0
            local.get 5
            call_indirect (type 0)
            i64.const 0
            local.set 7
            br 1 (;@3;)
          end
          local.get 1
          i64.load
          local.get 9
          i64.add
          local.set 7
        end
        local.get 10
        local.get 8
        local.get 11
        select
        local.set 8
        local.get 1
        local.get 7
        i64.store
        local.get 4
        local.get 9
        i64.sub
        local.tee 4
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
      end
    end)
  (func $cf_blockwise_acc_pad (type 20) (param i32 i32 i64 i32 i32 i32 i64 i32 i32)
    (local i32 i64 i64 i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 9
    global.set $__stack_pointer
    local.get 9
    local.get 3
    i32.store8 offset=11
    local.get 9
    local.get 5
    i32.store8 offset=10
    local.get 9
    i32.const 0
    i32.load
    i32.store offset=12
    block  ;; label = @1
      block  ;; label = @2
        local.get 6
        i64.const 2
        i64.gt_u
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 6
            i32.wrap_i64
            br_table 3 (;@1;) 0 (;@4;) 1 (;@3;) 3 (;@1;)
          end
          local.get 9
          local.get 5
          local.get 3
          i32.xor
          i32.store8 offset=11
          local.get 0
          local.get 1
          local.get 2
          local.get 9
          i32.const 11
          i32.add
          i64.const 1
          local.get 7
          local.get 7
          local.get 8
          call $cf_blockwise_accumulate_final
          br 2 (;@1;)
        end
        local.get 0
        local.get 1
        local.get 2
        local.get 9
        i32.const 11
        i32.add
        i64.const 1
        local.get 7
        local.get 7
        local.get 8
        call $cf_blockwise_accumulate_final
        local.get 0
        local.get 1
        local.get 2
        local.get 9
        i32.const 10
        i32.add
        i64.const 1
        local.get 7
        local.get 7
        local.get 8
        call $cf_blockwise_accumulate_final
        br 1 (;@1;)
      end
      local.get 0
      local.get 1
      local.get 2
      local.get 9
      i32.const 11
      i32.add
      i64.const 1
      local.get 7
      local.get 7
      local.get 8
      call $cf_blockwise_accumulate_final
      block  ;; label = @2
        local.get 5
        local.get 4
        i32.eq
        br_if 0 (;@2;)
        local.get 6
        i64.const -2
        i64.add
        local.set 10
        local.get 1
        i64.load
        local.set 6
        i32.const 0
        local.set 3
        loop  ;; label = @3
          local.get 10
          local.get 2
          local.get 6
          i64.sub
          local.tee 11
          local.get 10
          local.get 11
          i64.lt_u
          select
          local.set 11
          block  ;; label = @4
            local.get 3
            br_if 0 (;@4;)
            local.get 0
            local.get 6
            i32.wrap_i64
            i32.add
            local.get 4
            local.get 11
            i32.wrap_i64
            call $memset
            drop
          end
          i32.const 1
          local.get 3
          local.get 11
          local.get 2
          i64.eq
          select
          local.set 12
          local.get 6
          i64.eqz
          local.set 13
          block  ;; label = @4
            block  ;; label = @5
              local.get 11
              local.get 6
              i64.add
              local.get 2
              i64.ne
              br_if 0 (;@5;)
              local.get 8
              local.get 0
              local.get 7
              call_indirect (type 0)
              i64.const 0
              local.set 6
              br 1 (;@4;)
            end
            local.get 1
            i64.load
            local.get 11
            i64.add
            local.set 6
          end
          local.get 12
          local.get 3
          local.get 13
          select
          local.set 3
          local.get 1
          local.get 6
          i64.store
          local.get 10
          local.get 11
          i64.sub
          local.tee 10
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
        end
        local.get 0
        local.get 1
        local.get 2
        local.get 9
        i32.const 10
        i32.add
        i64.const 1
        local.get 7
        local.get 7
        local.get 8
        call $cf_blockwise_accumulate_final
        br 1 (;@1;)
      end
      local.get 6
      i64.const -1
      i64.add
      local.set 10
      local.get 1
      i64.load
      local.set 6
      i32.const 0
      local.set 3
      loop  ;; label = @2
        local.get 10
        local.get 2
        local.get 6
        i64.sub
        local.tee 11
        local.get 10
        local.get 11
        i64.lt_u
        select
        local.set 11
        block  ;; label = @3
          local.get 3
          br_if 0 (;@3;)
          local.get 0
          local.get 6
          i32.wrap_i64
          i32.add
          local.get 5
          local.get 11
          i32.wrap_i64
          call $memset
          drop
        end
        i32.const 1
        local.get 3
        local.get 11
        local.get 2
        i64.eq
        select
        local.set 12
        local.get 6
        i64.eqz
        local.set 13
        block  ;; label = @3
          block  ;; label = @4
            local.get 11
            local.get 6
            i64.add
            local.get 2
            i64.ne
            br_if 0 (;@4;)
            local.get 8
            local.get 0
            local.get 7
            call_indirect (type 0)
            i64.const 0
            local.set 6
            br 1 (;@3;)
          end
          local.get 1
          i64.load
          local.get 11
          i64.add
          local.set 6
        end
        local.get 12
        local.get 3
        local.get 13
        select
        local.set 3
        local.get 1
        local.get 6
        i64.store
        local.get 10
        local.get 11
        i64.sub
        local.tee 10
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
      end
    end
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 9
      i32.load offset=12
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 9
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_pw_region_enroll (type 21) (param i32) (result i32)
    (local i32 i32 i32 i64 i32)
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
      i32.load offset=16
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=8
          local.tee 3
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          local.get 2
          i64.extend_i32_u
          local.tee 4
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          local.get 2
          i32.eqz
          br_if 0 (;@3;)
          local.get 4
          call $malloc
          local.tee 5
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        local.get 0
        i32.const 0
        local.get 2
        call $pw_region_enroll
        i32.store
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 5
        local.get 4
        local.get 3
        local.get 4
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 0
        local.get 5
        local.get 2
        call $pw_region_enroll
        i32.store
        i32.const 0
        local.set 1
      end
      local.get 5
      call $free
    end
    local.get 1)
  (func $sgx_pw_setup (type 21) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i64 i32 i64 i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 48
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=40
      local.set 2
      local.get 0
      i32.load offset=24
      local.set 3
      local.get 0
      i32.load offset=32
      local.set 4
      local.get 0
      i32.load offset=16
      local.tee 5
      i64.extend_i32_u
      local.set 6
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        local.tee 7
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        local.get 6
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 4
      i64.extend_i32_u
      local.set 8
      block  ;; label = @2
        local.get 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        local.get 8
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i64.const 4
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 9
      i32.const 0
      local.set 10
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 7
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.set 10
            local.get 5
            i32.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 6
              call $malloc
              local.tee 10
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 10
            local.get 6
            local.get 7
            local.get 6
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.set 7
            i32.const 1
            local.set 1
            i32.const 0
            local.set 9
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 3
              i32.eqz
              br_if 0 (;@5;)
              local.get 4
              i32.eqz
              br_if 0 (;@5;)
              block  ;; label = @6
                local.get 8
                call $malloc
                local.tee 9
                br_if 0 (;@6;)
                i32.const 0
                local.set 9
                i32.const 3
                local.set 1
                i32.const 0
                local.set 7
                br 2 (;@4;)
              end
              local.get 9
              i32.const 0
              local.get 8
              i32.wrap_i64
              call $memset
              drop
            end
            block  ;; label = @5
              block  ;; label = @6
                local.get 2
                br_if 0 (;@6;)
                i32.const 0
                local.set 7
                br 1 (;@5;)
              end
              block  ;; label = @6
                i64.const 4
                call $malloc
                local.tee 7
                br_if 0 (;@6;)
                i32.const 0
                local.set 7
                i32.const 3
                local.set 1
                br 2 (;@4;)
              end
              local.get 7
              i32.const 0
              i32.store
            end
            local.get 0
            local.get 10
            local.get 5
            local.get 9
            local.get 4
            local.get 7
            call $pw_setup
            i32.store
            block  ;; label = @5
              local.get 9
              i32.eqz
              br_if 0 (;@5;)
              i32.const 1
              local.set 1
              local.get 3
              local.get 8
              local.get 9
              local.get 8
              call $memcpy_s
              br_if 1 (;@4;)
            end
            block  ;; label = @5
              local.get 7
              br_if 0 (;@5;)
              i32.const 0
              local.set 1
              i32.const 0
              local.set 7
              br 1 (;@4;)
            end
            local.get 2
            i64.const 4
            local.get 7
            i64.const 4
            call $memcpy_s
            i32.const 0
            i32.ne
            local.set 1
          end
          local.get 10
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 10
        call $free
      end
      block  ;; label = @2
        local.get 9
        i32.eqz
        br_if 0 (;@2;)
        local.get 9
        call $free
      end
      local.get 7
      i32.eqz
      br_if 0 (;@1;)
      local.get 7
      call $free
    end
    local.get 1)
  (func $sgx_pw_check (type 21) (param i32) (result i32)
    (local i32 i32 i64 i32 i32 i64 i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 40
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=24
      local.set 2
      local.get 0
      i64.load offset=16
      local.set 3
      local.get 0
      i32.load offset=32
      local.set 4
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        local.tee 5
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        local.get 3
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 4
      i64.extend_i32_u
      local.set 6
      block  ;; label = @2
        local.get 2
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        local.get 6
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 7
      i32.const 0
      local.set 8
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 5
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.set 8
            local.get 3
            i64.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 3
              call $malloc
              local.tee 8
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 8
            local.get 3
            local.get 5
            local.get 3
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 1
            i32.const 0
            local.set 7
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.eqz
              br_if 0 (;@5;)
              local.get 4
              i32.eqz
              br_if 0 (;@5;)
              block  ;; label = @6
                local.get 6
                call $malloc
                local.tee 7
                br_if 0 (;@6;)
                i32.const 0
                local.set 7
                i32.const 3
                local.set 1
                br 2 (;@4;)
              end
              i32.const 1
              local.set 1
              local.get 7
              local.get 6
              local.get 2
              local.get 6
              call $memcpy_s
              br_if 1 (;@4;)
            end
            local.get 0
            local.get 8
            local.get 3
            local.get 7
            local.get 4
            call $pw_check
            i32.store
            i32.const 0
            local.set 1
          end
          local.get 8
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 8
        call $free
      end
      local.get 7
      i32.eqz
      br_if 0 (;@1;)
      local.get 7
      call $free
    end
    local.get 1)
  (func $emit_debug (type 21) (param i32) (result i32)
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
  (func $cf_hmac_init (type 22) (param i32 i32 i32 i64)
    (local i32 i32 i64 i64 i64 i64 i32)
    global.get $__stack_pointer
    i32.const 272
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    i32.const 0
    i32.load
    i32.store offset=268
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i32.const 0
        i32.const 728
        call $memset
        local.tee 5
        i32.load8_u
        drop
        local.get 5
        local.get 1
        i32.store
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i64.load offset=8
            local.tee 6
            local.get 3
            i64.ge_u
            br_if 0 (;@4;)
            local.get 1
            i64.load
            local.get 6
            i64.gt_u
            br_if 2 (;@2;)
            local.get 1
            local.get 2
            local.get 3
            local.get 4
            i32.const 128
            i32.add
            call $cf_hash
            local.get 1
            i64.load offset=8
            local.set 6
            local.get 1
            i64.load
            local.set 3
            br 1 (;@3;)
          end
          local.get 4
          i32.const 128
          i32.add
          local.get 2
          i32.eq
          br_if 0 (;@3;)
          local.get 4
          i32.const 128
          i32.add
          local.get 2
          local.get 3
          i32.wrap_i64
          call $memcpy
          drop
        end
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              local.get 6
              local.get 3
              i64.le_u
              br_if 0 (;@5;)
              local.get 4
              i32.const 128
              i32.add
              local.get 3
              i32.wrap_i64
              i32.add
              i32.const 0
              local.get 6
              local.get 3
              i64.sub
              i32.wrap_i64
              call $memset
              drop
              br 1 (;@4;)
            end
            local.get 6
            i64.eqz
            br_if 1 (;@3;)
          end
          i64.const 0
          local.set 7
          block  ;; label = @4
            local.get 6
            i64.const 8
            i64.lt_u
            br_if 0 (;@4;)
            i64.const 0
            local.set 7
            block  ;; label = @5
              local.get 6
              i64.const 32
              i64.lt_u
              br_if 0 (;@5;)
              local.get 6
              i64.const -32
              i64.and
              local.tee 7
              i64.const -32
              i64.add
              local.tee 3
              i64.const 5
              i64.shr_u
              i64.const 1
              i64.add
              local.tee 8
              i64.const 1
              i64.and
              local.set 9
              block  ;; label = @6
                block  ;; label = @7
                  local.get 3
                  i64.eqz
                  i32.eqz
                  br_if 0 (;@7;)
                  i64.const 0
                  local.set 3
                  br 1 (;@6;)
                end
                i64.const 0
                local.get 8
                i64.const 1152921504606846974
                i64.and
                i64.sub
                local.set 8
                i32.const 0
                local.set 10
                i64.const 0
                local.set 3
                loop  ;; label = @7
                  local.get 4
                  local.get 10
                  i32.add
                  local.tee 0
                  local.get 4
                  i32.const 128
                  i32.add
                  local.get 10
                  i32.add
                  local.tee 2
                  i32.load8_u offset=8
                  i32.const 54
                  i32.xor
                  i32.store8 offset=8
                  local.get 0
                  local.get 2
                  i32.load8_u offset=4
                  i32.const 54
                  i32.xor
                  i32.store8 offset=4
                  local.get 0
                  local.get 2
                  i32.load8_u offset=2
                  i32.const 54
                  i32.xor
                  i32.store8 offset=2
                  local.get 0
                  local.get 2
                  i32.load8_u offset=1
                  i32.const 54
                  i32.xor
                  i32.store8 offset=1
                  local.get 0
                  local.get 2
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 31
                  i32.add
                  local.get 2
                  i32.const 31
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 30
                  i32.add
                  local.get 2
                  i32.const 30
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 29
                  i32.add
                  local.get 2
                  i32.const 29
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 28
                  i32.add
                  local.get 2
                  i32.const 28
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 27
                  i32.add
                  local.get 2
                  i32.const 27
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 26
                  i32.add
                  local.get 2
                  i32.const 26
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 25
                  i32.add
                  local.get 2
                  i32.const 25
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 24
                  i32.add
                  local.get 2
                  i32.const 24
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 23
                  i32.add
                  local.get 2
                  i32.const 23
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 22
                  i32.add
                  local.get 2
                  i32.const 22
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 21
                  i32.add
                  local.get 2
                  i32.const 21
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 20
                  i32.add
                  local.get 2
                  i32.const 20
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 19
                  i32.add
                  local.get 2
                  i32.const 19
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 18
                  i32.add
                  local.get 2
                  i32.const 18
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 17
                  i32.add
                  local.get 2
                  i32.const 17
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 16
                  i32.add
                  local.get 2
                  i32.const 16
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 15
                  i32.add
                  local.get 2
                  i32.const 15
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 14
                  i32.add
                  local.get 2
                  i32.const 14
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 13
                  i32.add
                  local.get 2
                  i32.const 13
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 12
                  i32.add
                  local.get 2
                  i32.const 12
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 11
                  i32.add
                  local.get 2
                  i32.const 11
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 10
                  i32.add
                  local.get 2
                  i32.const 10
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 9
                  i32.add
                  local.get 2
                  i32.const 9
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 7
                  i32.add
                  local.get 2
                  i32.const 7
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 6
                  i32.add
                  local.get 2
                  i32.const 6
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 5
                  i32.add
                  local.get 2
                  i32.const 5
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 3
                  i32.add
                  local.get 2
                  i32.const 3
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 63
                  i32.add
                  local.get 2
                  i32.const 63
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 62
                  i32.add
                  local.get 2
                  i32.const 62
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 61
                  i32.add
                  local.get 2
                  i32.const 61
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 60
                  i32.add
                  local.get 2
                  i32.const 60
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 59
                  i32.add
                  local.get 2
                  i32.const 59
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 58
                  i32.add
                  local.get 2
                  i32.const 58
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 57
                  i32.add
                  local.get 2
                  i32.const 57
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 56
                  i32.add
                  local.get 2
                  i32.const 56
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 55
                  i32.add
                  local.get 2
                  i32.const 55
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 54
                  i32.add
                  local.get 2
                  i32.const 54
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 53
                  i32.add
                  local.get 2
                  i32.const 53
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 52
                  i32.add
                  local.get 2
                  i32.const 52
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 51
                  i32.add
                  local.get 2
                  i32.const 51
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 50
                  i32.add
                  local.get 2
                  i32.const 50
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 49
                  i32.add
                  local.get 2
                  i32.const 49
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 48
                  i32.add
                  local.get 2
                  i32.const 48
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 47
                  i32.add
                  local.get 2
                  i32.const 47
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 46
                  i32.add
                  local.get 2
                  i32.const 46
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 45
                  i32.add
                  local.get 2
                  i32.const 45
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 44
                  i32.add
                  local.get 2
                  i32.const 44
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 43
                  i32.add
                  local.get 2
                  i32.const 43
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 42
                  i32.add
                  local.get 2
                  i32.const 42
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 41
                  i32.add
                  local.get 2
                  i32.const 41
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 40
                  i32.add
                  local.get 2
                  i32.const 40
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 39
                  i32.add
                  local.get 2
                  i32.const 39
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 38
                  i32.add
                  local.get 2
                  i32.const 38
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 37
                  i32.add
                  local.get 2
                  i32.const 37
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 36
                  i32.add
                  local.get 2
                  i32.const 36
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 35
                  i32.add
                  local.get 2
                  i32.const 35
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 34
                  i32.add
                  local.get 2
                  i32.const 34
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 33
                  i32.add
                  local.get 2
                  i32.const 33
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 32
                  i32.add
                  local.get 2
                  i32.const 32
                  i32.add
                  i32.load8_u
                  i32.const 54
                  i32.xor
                  i32.store8
                  local.get 10
                  i32.const 64
                  i32.add
                  local.set 10
                  local.get 3
                  i64.const 64
                  i64.add
                  local.set 3
                  local.get 8
                  i64.const 2
                  i64.add
                  local.tee 8
                  i64.const 0
                  i64.ne
                  br_if 0 (;@7;)
                end
              end
              block  ;; label = @6
                local.get 9
                i64.eqz
                br_if 0 (;@6;)
                local.get 4
                local.get 3
                i32.wrap_i64
                local.tee 2
                i32.add
                local.tee 0
                local.get 4
                i32.const 128
                i32.add
                local.get 2
                i32.add
                local.tee 2
                i32.load8_u offset=16
                i32.const 54
                i32.xor
                i32.store8 offset=16
                local.get 0
                local.get 2
                i32.load8_u offset=8
                i32.const 54
                i32.xor
                i32.store8 offset=8
                local.get 0
                local.get 2
                i32.load8_u offset=4
                i32.const 54
                i32.xor
                i32.store8 offset=4
                local.get 0
                local.get 2
                i32.load8_u offset=2
                i32.const 54
                i32.xor
                i32.store8 offset=2
                local.get 0
                local.get 2
                i32.load8_u offset=1
                i32.const 54
                i32.xor
                i32.store8 offset=1
                local.get 0
                local.get 2
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 31
                i32.add
                local.get 2
                i32.const 31
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 30
                i32.add
                local.get 2
                i32.const 30
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 29
                i32.add
                local.get 2
                i32.const 29
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 28
                i32.add
                local.get 2
                i32.const 28
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 27
                i32.add
                local.get 2
                i32.const 27
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 26
                i32.add
                local.get 2
                i32.const 26
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 25
                i32.add
                local.get 2
                i32.const 25
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 24
                i32.add
                local.get 2
                i32.const 24
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 23
                i32.add
                local.get 2
                i32.const 23
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 22
                i32.add
                local.get 2
                i32.const 22
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 21
                i32.add
                local.get 2
                i32.const 21
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 20
                i32.add
                local.get 2
                i32.const 20
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 19
                i32.add
                local.get 2
                i32.const 19
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 18
                i32.add
                local.get 2
                i32.const 18
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 17
                i32.add
                local.get 2
                i32.const 17
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 15
                i32.add
                local.get 2
                i32.const 15
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 14
                i32.add
                local.get 2
                i32.const 14
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 13
                i32.add
                local.get 2
                i32.const 13
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 12
                i32.add
                local.get 2
                i32.const 12
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 11
                i32.add
                local.get 2
                i32.const 11
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 10
                i32.add
                local.get 2
                i32.const 10
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 9
                i32.add
                local.get 2
                i32.const 9
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 7
                i32.add
                local.get 2
                i32.const 7
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 6
                i32.add
                local.get 2
                i32.const 6
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 5
                i32.add
                local.get 2
                i32.const 5
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
                local.get 0
                i32.const 3
                i32.add
                local.get 2
                i32.const 3
                i32.add
                i32.load8_u
                i32.const 54
                i32.xor
                i32.store8
              end
              local.get 6
              local.get 7
              i64.eq
              br_if 2 (;@3;)
              local.get 6
              i64.const 24
              i64.and
              i64.eqz
              br_if 1 (;@4;)
            end
            local.get 7
            local.get 6
            i64.const -8
            i64.and
            local.tee 8
            i64.sub
            local.set 3
            local.get 4
            i32.const 128
            i32.add
            local.get 7
            i32.wrap_i64
            local.tee 2
            i32.add
            local.set 0
            local.get 4
            local.get 2
            i32.add
            local.set 2
            loop  ;; label = @5
              local.get 2
              local.get 0
              i32.load8_u offset=4
              i32.const 54
              i32.xor
              i32.store8 offset=4
              local.get 2
              local.get 0
              i32.load8_u offset=2
              i32.const 54
              i32.xor
              i32.store8 offset=2
              local.get 2
              local.get 0
              i32.load8_u offset=1
              i32.const 54
              i32.xor
              i32.store8 offset=1
              local.get 2
              local.get 0
              i32.load8_u
              i32.const 54
              i32.xor
              i32.store8
              local.get 2
              i32.const 7
              i32.add
              local.get 0
              i32.const 7
              i32.add
              i32.load8_u
              i32.const 54
              i32.xor
              i32.store8
              local.get 2
              i32.const 6
              i32.add
              local.get 0
              i32.const 6
              i32.add
              i32.load8_u
              i32.const 54
              i32.xor
              i32.store8
              local.get 2
              i32.const 5
              i32.add
              local.get 0
              i32.const 5
              i32.add
              i32.load8_u
              i32.const 54
              i32.xor
              i32.store8
              local.get 2
              i32.const 3
              i32.add
              local.get 0
              i32.const 3
              i32.add
              i32.load8_u
              i32.const 54
              i32.xor
              i32.store8
              local.get 0
              i32.const 8
              i32.add
              local.set 0
              local.get 2
              i32.const 8
              i32.add
              local.set 2
              local.get 3
              i64.const 8
              i64.add
              local.tee 3
              i64.const 0
              i64.ne
              br_if 0 (;@5;)
            end
            local.get 8
            local.set 7
            local.get 6
            local.get 8
            i64.eq
            br_if 1 (;@3;)
          end
          local.get 6
          local.get 7
          i64.sub
          local.set 3
          local.get 4
          i32.const 128
          i32.add
          local.get 7
          i32.wrap_i64
          local.tee 2
          i32.add
          local.set 0
          local.get 4
          local.get 2
          i32.add
          local.set 2
          loop  ;; label = @4
            local.get 2
            local.get 0
            i32.load8_u
            i32.const 54
            i32.xor
            i32.store8
            local.get 0
            i32.const 1
            i32.add
            local.set 0
            local.get 2
            i32.const 1
            i32.add
            local.set 2
            local.get 3
            i64.const -1
            i64.add
            local.tee 3
            i64.const 0
            i64.ne
            br_if 0 (;@4;)
          end
        end
        local.get 5
        i32.const 8
        i32.add
        local.tee 0
        local.get 1
        i32.load offset=16
        call_indirect (type 1)
        local.get 0
        local.get 4
        local.get 1
        i64.load offset=8
        local.get 1
        i32.load offset=20
        call_indirect (type 2)
        block  ;; label = @3
          local.get 1
          i64.load offset=8
          local.tee 6
          i64.eqz
          br_if 0 (;@3;)
          i64.const 0
          local.set 7
          block  ;; label = @4
            local.get 6
            i64.const 8
            i64.lt_u
            br_if 0 (;@4;)
            i64.const 0
            local.set 7
            block  ;; label = @5
              local.get 6
              i64.const 32
              i64.lt_u
              br_if 0 (;@5;)
              local.get 6
              i64.const -32
              i64.and
              local.tee 7
              i64.const -32
              i64.add
              local.tee 3
              i64.const 5
              i64.shr_u
              i64.const 1
              i64.add
              local.tee 8
              i64.const 1
              i64.and
              local.set 9
              block  ;; label = @6
                block  ;; label = @7
                  local.get 3
                  i64.eqz
                  i32.eqz
                  br_if 0 (;@7;)
                  i64.const 0
                  local.set 3
                  br 1 (;@6;)
                end
                i64.const 0
                local.get 8
                i64.const 1152921504606846974
                i64.and
                i64.sub
                local.set 8
                i32.const 0
                local.set 10
                i64.const 0
                local.set 3
                loop  ;; label = @7
                  local.get 4
                  local.get 10
                  i32.add
                  local.tee 0
                  local.get 4
                  i32.const 128
                  i32.add
                  local.get 10
                  i32.add
                  local.tee 2
                  i32.load8_u offset=8
                  i32.const 92
                  i32.xor
                  i32.store8 offset=8
                  local.get 0
                  local.get 2
                  i32.load8_u offset=4
                  i32.const 92
                  i32.xor
                  i32.store8 offset=4
                  local.get 0
                  local.get 2
                  i32.load8_u offset=2
                  i32.const 92
                  i32.xor
                  i32.store8 offset=2
                  local.get 0
                  local.get 2
                  i32.load8_u offset=1
                  i32.const 92
                  i32.xor
                  i32.store8 offset=1
                  local.get 0
                  local.get 2
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 31
                  i32.add
                  local.get 2
                  i32.const 31
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 30
                  i32.add
                  local.get 2
                  i32.const 30
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 29
                  i32.add
                  local.get 2
                  i32.const 29
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 28
                  i32.add
                  local.get 2
                  i32.const 28
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 27
                  i32.add
                  local.get 2
                  i32.const 27
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 26
                  i32.add
                  local.get 2
                  i32.const 26
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 25
                  i32.add
                  local.get 2
                  i32.const 25
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 24
                  i32.add
                  local.get 2
                  i32.const 24
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 23
                  i32.add
                  local.get 2
                  i32.const 23
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 22
                  i32.add
                  local.get 2
                  i32.const 22
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 21
                  i32.add
                  local.get 2
                  i32.const 21
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 20
                  i32.add
                  local.get 2
                  i32.const 20
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 19
                  i32.add
                  local.get 2
                  i32.const 19
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 18
                  i32.add
                  local.get 2
                  i32.const 18
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 17
                  i32.add
                  local.get 2
                  i32.const 17
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 16
                  i32.add
                  local.get 2
                  i32.const 16
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 15
                  i32.add
                  local.get 2
                  i32.const 15
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 14
                  i32.add
                  local.get 2
                  i32.const 14
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 13
                  i32.add
                  local.get 2
                  i32.const 13
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 12
                  i32.add
                  local.get 2
                  i32.const 12
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 11
                  i32.add
                  local.get 2
                  i32.const 11
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 10
                  i32.add
                  local.get 2
                  i32.const 10
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 9
                  i32.add
                  local.get 2
                  i32.const 9
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 7
                  i32.add
                  local.get 2
                  i32.const 7
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 6
                  i32.add
                  local.get 2
                  i32.const 6
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 5
                  i32.add
                  local.get 2
                  i32.const 5
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 3
                  i32.add
                  local.get 2
                  i32.const 3
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 63
                  i32.add
                  local.get 2
                  i32.const 63
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 62
                  i32.add
                  local.get 2
                  i32.const 62
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 61
                  i32.add
                  local.get 2
                  i32.const 61
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 60
                  i32.add
                  local.get 2
                  i32.const 60
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 59
                  i32.add
                  local.get 2
                  i32.const 59
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 58
                  i32.add
                  local.get 2
                  i32.const 58
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 57
                  i32.add
                  local.get 2
                  i32.const 57
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 56
                  i32.add
                  local.get 2
                  i32.const 56
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 55
                  i32.add
                  local.get 2
                  i32.const 55
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 54
                  i32.add
                  local.get 2
                  i32.const 54
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 53
                  i32.add
                  local.get 2
                  i32.const 53
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 52
                  i32.add
                  local.get 2
                  i32.const 52
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 51
                  i32.add
                  local.get 2
                  i32.const 51
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 50
                  i32.add
                  local.get 2
                  i32.const 50
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 49
                  i32.add
                  local.get 2
                  i32.const 49
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 48
                  i32.add
                  local.get 2
                  i32.const 48
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 47
                  i32.add
                  local.get 2
                  i32.const 47
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 46
                  i32.add
                  local.get 2
                  i32.const 46
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 45
                  i32.add
                  local.get 2
                  i32.const 45
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 44
                  i32.add
                  local.get 2
                  i32.const 44
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 43
                  i32.add
                  local.get 2
                  i32.const 43
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 42
                  i32.add
                  local.get 2
                  i32.const 42
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 41
                  i32.add
                  local.get 2
                  i32.const 41
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 40
                  i32.add
                  local.get 2
                  i32.const 40
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 39
                  i32.add
                  local.get 2
                  i32.const 39
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 38
                  i32.add
                  local.get 2
                  i32.const 38
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 37
                  i32.add
                  local.get 2
                  i32.const 37
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 36
                  i32.add
                  local.get 2
                  i32.const 36
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 35
                  i32.add
                  local.get 2
                  i32.const 35
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 34
                  i32.add
                  local.get 2
                  i32.const 34
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 33
                  i32.add
                  local.get 2
                  i32.const 33
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 0
                  i32.const 32
                  i32.add
                  local.get 2
                  i32.const 32
                  i32.add
                  i32.load8_u
                  i32.const 92
                  i32.xor
                  i32.store8
                  local.get 10
                  i32.const 64
                  i32.add
                  local.set 10
                  local.get 3
                  i64.const 64
                  i64.add
                  local.set 3
                  local.get 8
                  i64.const 2
                  i64.add
                  local.tee 8
                  i64.const 0
                  i64.ne
                  br_if 0 (;@7;)
                end
              end
              block  ;; label = @6
                local.get 9
                i64.eqz
                br_if 0 (;@6;)
                local.get 4
                local.get 3
                i32.wrap_i64
                local.tee 2
                i32.add
                local.tee 0
                local.get 4
                i32.const 128
                i32.add
                local.get 2
                i32.add
                local.tee 2
                i32.load8_u offset=16
                i32.const 92
                i32.xor
                i32.store8 offset=16
                local.get 0
                local.get 2
                i32.load8_u offset=8
                i32.const 92
                i32.xor
                i32.store8 offset=8
                local.get 0
                local.get 2
                i32.load8_u offset=4
                i32.const 92
                i32.xor
                i32.store8 offset=4
                local.get 0
                local.get 2
                i32.load8_u offset=2
                i32.const 92
                i32.xor
                i32.store8 offset=2
                local.get 0
                local.get 2
                i32.load8_u offset=1
                i32.const 92
                i32.xor
                i32.store8 offset=1
                local.get 0
                local.get 2
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 31
                i32.add
                local.get 2
                i32.const 31
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 30
                i32.add
                local.get 2
                i32.const 30
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 29
                i32.add
                local.get 2
                i32.const 29
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 28
                i32.add
                local.get 2
                i32.const 28
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 27
                i32.add
                local.get 2
                i32.const 27
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 26
                i32.add
                local.get 2
                i32.const 26
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 25
                i32.add
                local.get 2
                i32.const 25
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 24
                i32.add
                local.get 2
                i32.const 24
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 23
                i32.add
                local.get 2
                i32.const 23
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 22
                i32.add
                local.get 2
                i32.const 22
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 21
                i32.add
                local.get 2
                i32.const 21
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 20
                i32.add
                local.get 2
                i32.const 20
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 19
                i32.add
                local.get 2
                i32.const 19
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 18
                i32.add
                local.get 2
                i32.const 18
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 17
                i32.add
                local.get 2
                i32.const 17
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 15
                i32.add
                local.get 2
                i32.const 15
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 14
                i32.add
                local.get 2
                i32.const 14
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 13
                i32.add
                local.get 2
                i32.const 13
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 12
                i32.add
                local.get 2
                i32.const 12
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 11
                i32.add
                local.get 2
                i32.const 11
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 10
                i32.add
                local.get 2
                i32.const 10
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 9
                i32.add
                local.get 2
                i32.const 9
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 7
                i32.add
                local.get 2
                i32.const 7
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 6
                i32.add
                local.get 2
                i32.const 6
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 5
                i32.add
                local.get 2
                i32.const 5
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
                local.get 0
                i32.const 3
                i32.add
                local.get 2
                i32.const 3
                i32.add
                i32.load8_u
                i32.const 92
                i32.xor
                i32.store8
              end
              local.get 6
              local.get 7
              i64.eq
              br_if 2 (;@3;)
              local.get 6
              i64.const 24
              i64.and
              i64.eqz
              br_if 1 (;@4;)
            end
            local.get 7
            local.get 6
            i64.const -8
            i64.and
            local.tee 8
            i64.sub
            local.set 3
            local.get 4
            i32.const 128
            i32.add
            local.get 7
            i32.wrap_i64
            local.tee 2
            i32.add
            local.set 0
            local.get 4
            local.get 2
            i32.add
            local.set 2
            loop  ;; label = @5
              local.get 2
              local.get 0
              i32.load8_u offset=4
              i32.const 92
              i32.xor
              i32.store8 offset=4
              local.get 2
              local.get 0
              i32.load8_u offset=2
              i32.const 92
              i32.xor
              i32.store8 offset=2
              local.get 2
              local.get 0
              i32.load8_u offset=1
              i32.const 92
              i32.xor
              i32.store8 offset=1
              local.get 2
              local.get 0
              i32.load8_u
              i32.const 92
              i32.xor
              i32.store8
              local.get 2
              i32.const 7
              i32.add
              local.get 0
              i32.const 7
              i32.add
              i32.load8_u
              i32.const 92
              i32.xor
              i32.store8
              local.get 2
              i32.const 6
              i32.add
              local.get 0
              i32.const 6
              i32.add
              i32.load8_u
              i32.const 92
              i32.xor
              i32.store8
              local.get 2
              i32.const 5
              i32.add
              local.get 0
              i32.const 5
              i32.add
              i32.load8_u
              i32.const 92
              i32.xor
              i32.store8
              local.get 2
              i32.const 3
              i32.add
              local.get 0
              i32.const 3
              i32.add
              i32.load8_u
              i32.const 92
              i32.xor
              i32.store8
              local.get 0
              i32.const 8
              i32.add
              local.set 0
              local.get 2
              i32.const 8
              i32.add
              local.set 2
              local.get 3
              i64.const 8
              i64.add
              local.tee 3
              i64.const 0
              i64.ne
              br_if 0 (;@5;)
            end
            local.get 8
            local.set 7
            local.get 6
            local.get 8
            i64.eq
            br_if 1 (;@3;)
          end
          local.get 6
          local.get 7
          i64.sub
          local.set 3
          local.get 4
          i32.const 128
          i32.add
          local.get 7
          i32.wrap_i64
          local.tee 2
          i32.add
          local.set 0
          local.get 4
          local.get 2
          i32.add
          local.set 2
          loop  ;; label = @4
            local.get 2
            local.get 0
            i32.load8_u
            i32.const 92
            i32.xor
            i32.store8
            local.get 0
            i32.const 1
            i32.add
            local.set 0
            local.get 2
            i32.const 1
            i32.add
            local.set 2
            local.get 3
            i64.const -1
            i64.add
            local.tee 3
            i64.const 0
            i64.ne
            br_if 0 (;@4;)
          end
        end
        local.get 5
        i32.const 368
        i32.add
        local.tee 0
        local.get 1
        i32.load offset=16
        call_indirect (type 1)
        local.get 0
        local.get 4
        local.get 1
        i64.load offset=8
        local.get 1
        i32.load offset=20
        call_indirect (type 2)
        local.get 4
        i32.const 0
        i32.const 128
        call $memset
        local.tee 0
        i32.load8_u
        drop
        local.get 0
        i32.const 128
        i32.add
        i32.const 0
        i32.const 128
        call $memset
        drop
        local.get 0
        i32.load8_u offset=128
        drop
        i32.const 0
        i32.load
        local.get 0
        i32.load offset=268
        i32.ne
        br_if 1 (;@1;)
        local.get 0
        i32.const 272
        i32.add
        global.set $__stack_pointer
        return
      end
      call $abort
      unreachable
    end
    call $__stack_chk_fail
    unreachable)
  (func $cf_hmac_update (type 2) (param i32 i32 i64)
    (local i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i32.load
        local.tee 3
        br_if 1 (;@1;)
      end
      call $abort
      unreachable
    end
    local.get 0
    i32.const 8
    i32.add
    local.get 1
    local.get 2
    local.get 3
    i32.load offset=20
    call_indirect (type 2))
  (func $cf_hmac_finish (type 0) (param i32 i32)
    (local i32 i32 i32)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=76
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i32.load
        local.tee 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i32.const 8
        i32.add
        local.get 2
        local.get 3
        i32.load offset=24
        call_indirect (type 0)
        local.get 0
        i32.const 368
        i32.add
        local.tee 3
        local.get 2
        local.get 0
        i32.load
        local.tee 4
        i64.load
        local.get 4
        i32.load offset=20
        call_indirect (type 2)
        local.get 3
        local.get 1
        local.get 0
        i32.load
        i32.load offset=24
        call_indirect (type 0)
        local.get 0
        i32.const 0
        i32.const 728
        call $memset
        i32.load8_u
        drop
        i32.const 0
        i32.load
        local.get 2
        i32.load offset=76
        i32.ne
        br_if 1 (;@1;)
        local.get 2
        i32.const 80
        i32.add
        global.set $__stack_pointer
        return
      end
      call $abort
      unreachable
    end
    call $__stack_chk_fail
    unreachable)
  (func $cf_hash (type 23) (param i32 i32 i64 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 368
    i32.sub
    local.tee 4
    global.set $__stack_pointer
    local.get 4
    i32.const 0
    i32.load
    i32.store offset=364
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 4
        local.get 0
        i32.load offset=16
        call_indirect (type 1)
        local.get 4
        local.get 1
        local.get 2
        local.get 0
        i32.load offset=20
        call_indirect (type 2)
        local.get 4
        local.get 3
        local.get 0
        i32.load offset=24
        call_indirect (type 0)
        local.get 4
        i32.const 0
        i32.const 360
        call $memset
        local.tee 4
        i32.load8_u
        drop
        i32.const 0
        i32.load
        local.get 4
        i32.load offset=364
        i32.ne
        br_if 1 (;@1;)
        local.get 4
        i32.const 368
        i32.add
        global.set $__stack_pointer
        return
      end
      call $abort
      unreachable
    end
    call $__stack_chk_fail
    unreachable)
  (func $cf_hmac (type 24) (param i32 i64 i32 i64 i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 816
    i32.sub
    local.tee 6
    global.set $__stack_pointer
    local.get 6
    i32.const 0
    i32.load
    i32.store offset=812
    block  ;; label = @1
      block  ;; label = @2
        local.get 4
        i32.eqz
        br_if 0 (;@2;)
        local.get 5
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        i32.const 8
        i32.add
        local.get 5
        local.get 0
        local.get 1
        call $cf_hmac_init
        local.get 6
        i32.load offset=8
        local.tee 5
        i32.eqz
        br_if 0 (;@2;)
        local.get 6
        i32.const 16
        i32.add
        local.tee 0
        local.get 2
        local.get 3
        local.get 5
        i32.load offset=20
        call_indirect (type 2)
        local.get 6
        i32.load offset=8
        local.tee 5
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 6
        i32.const 736
        i32.add
        local.get 5
        i32.load offset=24
        call_indirect (type 0)
        local.get 6
        i32.const 376
        i32.add
        local.tee 5
        local.get 6
        i32.const 736
        i32.add
        local.get 6
        i32.load offset=8
        local.tee 0
        i64.load
        local.get 0
        i32.load offset=20
        call_indirect (type 2)
        local.get 5
        local.get 4
        local.get 6
        i32.load offset=8
        i32.load offset=24
        call_indirect (type 0)
        local.get 6
        i32.const 8
        i32.add
        i32.const 0
        i32.const 728
        call $memset
        drop
        local.get 6
        i32.load8_u offset=8
        drop
        i32.const 0
        i32.load
        local.get 6
        i32.load offset=812
        i32.ne
        br_if 1 (;@1;)
        local.get 6
        i32.const 816
        i32.add
        global.set $__stack_pointer
        return
      end
      call $abort
      unreachable
    end
    call $__stack_chk_fail
    unreachable)
  (func $cf_sha224_init (type 1) (param i32)
    local.get 0
    i32.const 32
    i32.add
    i32.const 0
    i32.const 80
    call $memset
    drop
    local.get 0
    i32.const 24
    i32.add
    i64.const -4685344894838272089
    i64.store
    local.get 0
    i64.const 7518782744944446257
    i64.store offset=16
    local.get 0
    i64.const -644479594506691305
    i64.store offset=8
    local.get 0
    i64.const 3926247204440088280
    i64.store)
  (func $cf_sha224_update (type 2) (param i32 i32 i64)
    local.get 0
    i32.const 32
    i32.add
    local.get 0
    i32.const 104
    i32.add
    i64.const 64
    local.get 1
    local.get 2
    i32.const 1
    local.get 0
    call $cf_blockwise_accumulate)
  (func $sha256_update_block (type 0) (param i32 i32)
    (local i32 i64 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64)
    global.get $__stack_pointer
    i32.const 80
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=76
    i64.const 0
    local.set 3
    local.get 0
    i32.load
    local.tee 4
    local.set 5
    local.get 0
    i32.load offset=28
    local.tee 6
    local.set 7
    local.get 0
    i32.load offset=24
    local.tee 8
    local.set 9
    local.get 0
    i32.load offset=20
    local.tee 10
    local.set 11
    local.get 0
    i32.load offset=16
    local.tee 12
    local.set 13
    local.get 0
    i32.load offset=12
    local.tee 14
    local.set 15
    local.get 0
    i32.load offset=8
    local.tee 16
    local.set 17
    local.get 0
    i32.load offset=4
    local.tee 18
    local.set 19
    loop  ;; label = @1
      local.get 19
      local.set 20
      local.get 17
      local.set 21
      local.get 13
      local.set 22
      local.get 11
      local.set 23
      local.get 9
      local.set 24
      local.get 5
      local.set 19
      block  ;; label = @2
        block  ;; label = @3
          local.get 3
          i64.const 15
          i64.gt_u
          br_if 0 (;@3;)
          local.get 2
          local.get 3
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          local.get 1
          i32.load align=1
          local.tee 5
          i32.const 24
          i32.shl
          local.get 5
          i32.const 8
          i32.shl
          i32.const 16711680
          i32.and
          i32.or
          local.get 5
          i32.const 8
          i32.shr_u
          i32.const 65280
          i32.and
          local.get 5
          i32.const 24
          i32.shr_u
          i32.or
          i32.or
          local.tee 5
          i32.store
          local.get 3
          i64.const 1
          i64.add
          local.set 25
          local.get 1
          i32.const 4
          i32.add
          local.set 1
          br 1 (;@2;)
        end
        local.get 2
        local.get 3
        i32.wrap_i64
        local.tee 5
        i32.const 15
        i32.and
        i32.const 2
        i32.shl
        i32.add
        local.tee 9
        local.get 2
        local.get 5
        i32.const 14
        i32.add
        i32.const 15
        i32.and
        i32.const 2
        i32.shl
        i32.add
        i32.load
        local.tee 13
        i32.const 15
        i32.rotl
        local.get 13
        i32.const 13
        i32.rotl
        i32.xor
        local.get 13
        i32.const 10
        i32.shr_u
        i32.xor
        local.get 2
        local.get 5
        i32.const 9
        i32.add
        i32.const 15
        i32.and
        i32.const 2
        i32.shl
        i32.add
        i32.load
        i32.add
        local.get 9
        i32.load
        i32.add
        local.get 2
        local.get 3
        i64.const 1
        i64.add
        local.tee 25
        i32.wrap_i64
        i32.const 15
        i32.and
        i32.const 2
        i32.shl
        i32.add
        i32.load
        local.tee 5
        i32.const 25
        i32.rotl
        local.get 5
        i32.const 14
        i32.rotl
        i32.xor
        local.get 5
        i32.const 3
        i32.shr_u
        i32.xor
        i32.add
        local.tee 5
        i32.store
      end
      local.get 19
      i32.const 30
      i32.rotl
      local.get 19
      i32.const 19
      i32.rotl
      i32.xor
      local.get 19
      i32.const 10
      i32.rotl
      i32.xor
      local.get 19
      local.get 21
      local.get 20
      i32.xor
      i32.and
      local.get 21
      local.get 20
      i32.and
      i32.xor
      i32.add
      local.get 22
      i32.const 26
      i32.rotl
      local.get 22
      i32.const 21
      i32.rotl
      i32.xor
      local.get 22
      i32.const 7
      i32.rotl
      i32.xor
      local.get 23
      local.get 22
      i32.and
      i32.add
      local.get 7
      i32.add
      local.get 24
      local.get 22
      i32.const -1
      i32.xor
      i32.and
      i32.add
      local.get 5
      i32.add
      local.get 3
      i32.wrap_i64
      i32.const 2
      i32.shl
      i32.const 1232
      i32.add
      i32.load
      i32.add
      local.tee 13
      i32.add
      local.set 5
      local.get 13
      local.get 15
      i32.add
      local.set 13
      local.get 25
      local.set 3
      local.get 24
      local.set 7
      local.get 23
      local.set 9
      local.get 22
      local.set 11
      local.get 21
      local.set 15
      local.get 20
      local.set 17
      local.get 25
      i64.const 64
      i64.ne
      br_if 0 (;@1;)
    end
    local.get 0
    local.get 24
    local.get 6
    i32.add
    i32.store offset=28
    local.get 0
    local.get 23
    local.get 8
    i32.add
    i32.store offset=24
    local.get 0
    local.get 22
    local.get 10
    i32.add
    i32.store offset=20
    local.get 0
    local.get 13
    local.get 12
    i32.add
    i32.store offset=16
    local.get 0
    local.get 21
    local.get 14
    i32.add
    i32.store offset=12
    local.get 0
    local.get 20
    local.get 16
    i32.add
    i32.store offset=8
    local.get 0
    local.get 19
    local.get 18
    i32.add
    i32.store offset=4
    local.get 0
    local.get 5
    local.get 4
    i32.add
    i32.store
    local.get 0
    local.get 0
    i32.load offset=96
    i32.const 1
    i32.add
    i32.store offset=96
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=76
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 80
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha224_digest (type 0) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 160
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=156
    local.get 2
    i32.const 40
    i32.add
    local.get 0
    i32.const 112
    call $memcpy
    drop
    local.get 2
    i32.const 40
    i32.add
    local.get 2
    call $cf_sha256_digest_final
    local.get 1
    i32.const 24
    i32.add
    local.get 2
    i32.const 24
    i32.add
    i32.load
    i32.store align=1
    local.get 1
    i32.const 16
    i32.add
    local.get 2
    i32.const 16
    i32.add
    i64.load
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    local.get 2
    i64.load offset=8
    i64.store align=1
    local.get 1
    local.get 2
    i64.load
    i64.store align=1
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=156
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 160
    i32.add
    global.set $__stack_pointer)
  (func $cf_sha256_digest_final (type 0) (param i32 i32)
    (local i32 i32 i32 i64)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=12
    local.get 0
    i32.const 32
    i32.add
    local.tee 3
    local.get 0
    i32.const 104
    i32.add
    local.tee 4
    i64.const 64
    i32.const 128
    i32.const 0
    i32.const 0
    i64.const 64
    local.get 0
    i64.load32_u offset=96
    i64.const 6
    i64.shl
    local.get 0
    i64.load offset=104
    i64.add
    local.tee 5
    i64.const 8
    i64.add
    i64.const 63
    i64.and
    i64.sub
    i32.const 1
    local.get 0
    call $cf_blockwise_acc_pad
    local.get 2
    local.get 5
    i32.wrap_i64
    i32.const 3
    i32.shl
    i32.store8 offset=11
    local.get 2
    local.get 5
    i64.const 5
    i64.shr_u
    i64.store8 offset=10
    local.get 2
    local.get 5
    i64.const 13
    i64.shr_u
    i64.store8 offset=9
    local.get 2
    local.get 5
    i64.const 21
    i64.shr_u
    i64.store8 offset=8
    local.get 2
    local.get 5
    i64.const 29
    i64.shr_u
    i64.store8 offset=7
    local.get 2
    local.get 5
    i64.const 37
    i64.shr_u
    i64.store8 offset=6
    local.get 2
    local.get 5
    i64.const 45
    i64.shr_u
    i64.store8 offset=5
    local.get 2
    local.get 5
    i64.const 53
    i64.shr_u
    i64.store8 offset=4
    local.get 3
    local.get 4
    i64.const 64
    local.get 2
    i32.const 4
    i32.add
    i64.const 8
    i32.const 1
    local.get 0
    call $cf_blockwise_accumulate
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i64.load offset=104
        i64.eqz
        i32.eqz
        br_if 0 (;@2;)
        local.get 1
        local.get 0
        i32.load
        local.tee 3
        i32.const 24
        i32.shl
        local.get 3
        i32.const 8
        i32.shl
        i32.const 16711680
        i32.and
        i32.or
        local.get 3
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 3
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        i32.store align=1
        local.get 1
        local.get 0
        i32.load offset=4
        local.tee 3
        i32.const 24
        i32.shl
        local.get 3
        i32.const 8
        i32.shl
        i32.const 16711680
        i32.and
        i32.or
        local.get 3
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 3
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        i32.store offset=4 align=1
        local.get 1
        local.get 0
        i32.load offset=8
        local.tee 3
        i32.const 24
        i32.shl
        local.get 3
        i32.const 8
        i32.shl
        i32.const 16711680
        i32.and
        i32.or
        local.get 3
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 3
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        i32.store offset=8 align=1
        local.get 1
        local.get 0
        i32.load offset=12
        local.tee 3
        i32.const 24
        i32.shl
        local.get 3
        i32.const 8
        i32.shl
        i32.const 16711680
        i32.and
        i32.or
        local.get 3
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 3
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        i32.store offset=12 align=1
        local.get 1
        local.get 0
        i32.load offset=16
        local.tee 3
        i32.const 24
        i32.shl
        local.get 3
        i32.const 8
        i32.shl
        i32.const 16711680
        i32.and
        i32.or
        local.get 3
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 3
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        i32.store offset=16 align=1
        local.get 1
        local.get 0
        i32.load offset=20
        local.tee 3
        i32.const 24
        i32.shl
        local.get 3
        i32.const 8
        i32.shl
        i32.const 16711680
        i32.and
        i32.or
        local.get 3
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 3
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        i32.store offset=20 align=1
        local.get 1
        local.get 0
        i32.load offset=24
        local.tee 3
        i32.const 24
        i32.shl
        local.get 3
        i32.const 8
        i32.shl
        i32.const 16711680
        i32.and
        i32.or
        local.get 3
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 3
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        i32.store offset=24 align=1
        local.get 1
        local.get 0
        i32.load offset=28
        local.tee 3
        i32.const 24
        i32.shl
        local.get 3
        i32.const 8
        i32.shl
        i32.const 16711680
        i32.and
        i32.or
        local.get 3
        i32.const 8
        i32.shr_u
        i32.const 65280
        i32.and
        local.get 3
        i32.const 24
        i32.shr_u
        i32.or
        i32.or
        i32.store offset=28 align=1
        local.get 0
        i32.const 0
        i32.const 112
        call $memset
        drop
        i32.const 0
        i32.load
        local.get 2
        i32.load offset=12
        i32.ne
        br_if 1 (;@1;)
        local.get 2
        i32.const 16
        i32.add
        global.set $__stack_pointer
        return
      end
      call $abort
      unreachable
    end
    call $__stack_chk_fail
    unreachable)
  (func $cf_sha256_init (type 1) (param i32)
    local.get 0
    i32.const 32
    i32.add
    i32.const 0
    i32.const 80
    call $memset
    drop
    local.get 0
    i32.const 24
    i32.add
    i64.const 6620516960021240235
    i64.store
    local.get 0
    i64.const -7276294671082564993
    i64.store offset=16
    local.get 0
    i64.const -6534734903820487822
    i64.store offset=8
    local.get 0
    i64.const -4942790177982912921
    i64.store)
  (func $cf_sha256_update (type 2) (param i32 i32 i64)
    local.get 0
    i32.const 32
    i32.add
    local.get 0
    i32.const 104
    i32.add
    i64.const 64
    local.get 1
    local.get 2
    i32.const 1
    local.get 0
    call $cf_blockwise_accumulate)
  (func $cf_sha256_digest (type 0) (param i32 i32)
    (local i32)
    global.get $__stack_pointer
    i32.const 128
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=124
    local.get 2
    i32.const 8
    i32.add
    local.get 0
    i32.const 112
    call $memcpy
    drop
    local.get 2
    i32.const 8
    i32.add
    local.get 1
    call $cf_sha256_digest_final
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=124
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 2
    i32.const 128
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
    i32.const 0
    i32.load
    i32.store offset=44
    local.get 0
    local.get 2
    call $cf_sha256_digest_final
    local.get 1
    i32.const 24
    i32.add
    local.get 2
    i32.const 24
    i32.add
    i32.load
    i32.store align=1
    local.get 1
    i32.const 16
    i32.add
    local.get 2
    i32.const 16
    i32.add
    i64.load
    i64.store align=1
    local.get 1
    i32.const 8
    i32.add
    local.get 2
    i64.load offset=8
    i64.store align=1
    local.get 1
    local.get 2
    i64.load
    i64.store align=1
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=44
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
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
  (export "cf_sha224_digest" (func $cf_sha224_digest))
  (export "cf_sha256_digest_final" (func $cf_sha256_digest_final))
  (export "cf_sha256_init" (func $cf_sha256_init))
  (export "cf_sha256_update" (func $cf_sha256_update))
  (export "cf_sha256_digest" (func $cf_sha256_digest))
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
