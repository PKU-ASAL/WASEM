(module
  (type (;0;) (func (param i32 i64) (result i32)))
  (type (;1;) (func (param i64) (result i32)))
  (type (;2;) (func (param i32 i64 i32 i64) (result i32)))
  (type (;3;) (func (param i32) (result i64)))
  (type (;4;) (func (param i32)))
  (type (;5;) (func (param i32 i32) (result i32)))
  (type (;6;) (func))
  (type (;7;) (func (param i32 i32 i32) (result i32)))
  (type (;8;) (func (param i32 i64 i32 i32) (result i32)))
  (type (;9;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;10;) (func (param i32) (result i32)))
  (type (;11;) (func (param i32 i32 i32 i32)))
  (type (;12;) (func (param i32 i32 i64) (result i32)))
  (type (;13;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;14;) (func (param i32 i32 i32 i32 i32 i32) (result i32)))
  (type (;15;) (func (result i32)))
  (type (;16;) (func (param i32 i32)))
  (type (;17;) (func (param f32)))
  (type (;18;) (func (param f64)))
  (type (;19;) (func (param i64)))
  (type (;20;) (func (param i32 i64)))
  (type (;21;) (func (param i32 i64) (result i64)))
  (type (;22;) (func (result i64)))
  (type (;23;) (func (param i32 i32 i32 i32 i64) (result i32)))
  (type (;24;) (func (param f64) (result f64)))
  (type (;25;) (func (param f64 f64) (result i32)))
  (type (;26;) (func (param f32 f32) (result i32)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "malloc" (func $malloc (type 1)))
  (import "env" "memcpy_s" (func $memcpy_s (type 2)))
  (import "env" "strlen" (func $strlen (type 3)))
  (import "env" "free" (func $free (type 4)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 1)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 5)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 6)))
  (import "env" "memset" (func $memset (type 7)))
  (import "env" "vsnprintf" (func $vsnprintf (type 8)))
  (import "env" "__stack_chk_fail" (func $__stack_chk_fail (type 6)))
  (import "env" "memcpy" (func $memcpy (type 7)))
  (import "env" "strstr" (func $strstr (type 5)))
  (import "env" "sgx_calc_sealed_data_size" (func $sgx_calc_sealed_data_size (type 5)))
  (import "env" "sgx_unseal_data" (func $sgx_unseal_data (type 9)))
  (import "env" "atoi" (func $atoi (type 10)))
  (import "env" "__assert" (func $__assert (type 11)))
  (import "env" "abort" (func $abort (type 6)))
  (import "env" "strncpy" (func $strncpy (type 12)))
  (import "env" "sgx_thread_mutex_lock" (func $sgx_thread_mutex_lock (type 10)))
  (import "env" "sgx_thread_mutex_unlock" (func $sgx_thread_mutex_unlock (type 10)))
  (import "env" "sgx_thread_cond_wait" (func $sgx_thread_cond_wait (type 5)))
  (import "env" "sgx_thread_cond_signal" (func $sgx_thread_cond_signal (type 10)))
  (import "env" "sgx_cpuid" (func $sgx_cpuid (type 5)))
  (import "env" "sgx_sha256_msg" (func $sgx_sha256_msg (type 7)))
  (import "env" "sgx_rijndael128_cmac_msg" (func $sgx_rijndael128_cmac_msg (type 13)))
  (import "env" "sgx_seal_data" (func $sgx_seal_data (type 14)))
  (func $__wasm_call_ctors (type 6))
  (func $sgx_process_log (type 10) (param i32) (result i32)
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
          call $process_log
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
    call $process_log
    i32.const 0)
  (func $process_log (type 4) (param i32)
    (local i32 i32 i32 i64 i64 i64 i32 i32 i32 i32 i64 i32 i32 i32 i64 i64 i64 i32)
    global.get $__stack_pointer
    i32.const 242080
    i32.sub
    local.tee 1
    global.set $__stack_pointer
    local.get 1
    i32.const 0
    i32.load
    i32.store offset=242076
    local.get 0
    call $strlen
    i32.wrap_i64
    local.get 1
    i32.const 240016
    i32.add
    i32.const 10
    call $itoa
    local.set 2
    i64.const 2048
    call $malloc
    local.set 3
    block  ;; label = @1
      block  ;; label = @2
        local.get 2
        call $strlen
        local.tee 4
        i64.eqz
        i32.eqz
        br_if 0 (;@2;)
        i64.const 0
        local.set 4
        br 1 (;@1;)
      end
      local.get 3
      local.get 1
      i32.const 240016
      i32.add
      local.get 4
      i32.wrap_i64
      call $memcpy
      drop
      local.get 4
      i64.const 4294967295
      i64.and
      local.set 4
    end
    block  ;; label = @1
      local.get 0
      call $strlen
      local.tee 5
      i64.eqz
      br_if 0 (;@1;)
      local.get 3
      local.get 4
      i32.wrap_i64
      i32.add
      local.get 0
      local.get 5
      i32.wrap_i64
      call $memcpy
      drop
    end
    block  ;; label = @1
      i32.const 0
      i32.load offset=4032
      local.tee 0
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      i64.const 0
      local.set 6
      loop  ;; label = @2
        block  ;; label = @3
          local.get 3
          local.get 6
          i32.wrap_i64
          i32.const 24
          i32.mul
          local.tee 7
          i32.const 3792
          i32.add
          i32.load
          call $strstr
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          call $strlen
          local.set 5
          block  ;; label = @4
            local.get 7
            i32.const 3808
            i32.add
            local.tee 2
            i32.load
            local.tee 8
            i32.const 4095
            i32.gt_u
            br_if 0 (;@4;)
            block  ;; label = @5
              local.get 5
              i32.wrap_i64
              local.tee 9
              i32.eqz
              br_if 0 (;@5;)
              local.get 7
              i32.const 3804
              i32.add
              local.set 10
              local.get 5
              i64.const 1
              i64.and
              local.set 11
              i64.const 0
              local.set 4
              block  ;; label = @6
                local.get 5
                i64.const 4294967295
                i64.and
                local.tee 5
                i64.const 1
                i64.eq
                br_if 0 (;@6;)
                local.get 5
                local.get 11
                i64.sub
                local.set 5
                i64.const 0
                local.set 4
                i32.const 1
                local.set 0
                loop  ;; label = @7
                  local.get 8
                  local.get 0
                  i32.add
                  local.get 10
                  i32.load
                  i32.add
                  i32.const -1
                  i32.add
                  local.get 3
                  local.get 0
                  i32.add
                  local.tee 8
                  i32.const -1
                  i32.add
                  i32.load8_u
                  i32.store8
                  local.get 10
                  i32.load
                  local.get 0
                  local.get 2
                  i32.load
                  i32.add
                  i32.add
                  local.get 8
                  i32.load8_u
                  i32.store8
                  local.get 0
                  i32.const 2
                  i32.add
                  local.set 0
                  local.get 2
                  i32.load
                  local.set 8
                  local.get 5
                  local.get 4
                  i64.const 2
                  i64.add
                  local.tee 4
                  i64.ne
                  br_if 0 (;@7;)
                end
              end
              local.get 11
              i64.eqz
              br_if 0 (;@5;)
              local.get 10
              i32.load
              local.get 8
              local.get 4
              i32.wrap_i64
              local.tee 0
              i32.add
              i32.add
              local.get 3
              local.get 0
              i32.add
              i32.load8_u
              i32.store8
              local.get 2
              i32.load
              local.set 8
            end
            local.get 2
            local.get 8
            local.get 9
            i32.add
            i32.store
            local.get 7
            i32.const 3812
            i32.add
            local.tee 0
            local.get 0
            i32.load
            i32.const 1
            i32.add
            i32.store
          end
          block  ;; label = @4
            block  ;; label = @5
              i32.const 0
              i32.load offset=3780
              local.tee 8
              br_if 0 (;@5;)
              i32.const 0
              i32.load offset=3760
              local.set 0
              local.get 0
              local.get 0
              call $strlen
              i32.wrap_i64
              i32.const 0
              call $get_next_message_key
              local.set 0
              br 1 (;@4;)
            end
            i32.const 0
            i32.load offset=4040
            local.set 0
            local.get 0
            local.get 0
            call $strlen
            i32.wrap_i64
            local.get 8
            call $get_next_message_key
            local.set 0
          end
          i32.const 0
          local.get 0
          i32.store offset=4040
          i32.const 0
          i32.const 0
          i32.load offset=3780
          i32.const 1
          i32.add
          i32.store offset=3780
          local.get 3
          local.get 3
          call $strlen
          i32.wrap_i64
          local.get 0
          call $get_mac
          local.set 8
          block  ;; label = @4
            i32.const 0
            i32.load offset=3780
            i32.const 3
            i32.ne
            br_if 0 (;@4;)
            i32.const 3214
            i32.const 0
            call $printf
            block  ;; label = @5
              block  ;; label = @6
                i32.const 0
                i32.load offset=3760
                br_if 0 (;@6;)
                i32.const 100
                local.set 0
                i32.const 0
                i32.const 100
                i32.store offset=3764
                i32.const 0
                i32.const 0
                i32.load offset=3768
                local.tee 10
                i32.store offset=3760
                br 1 (;@5;)
              end
              i32.const 0
              i32.const 0
              i32.load offset=3776
              local.tee 10
              i32.store offset=3760
              i32.const 0
              i32.const 0
              i32.load offset=3764
              i32.const 1
              i32.add
              local.tee 0
              i32.store offset=3764
            end
            i32.const 0
            local.get 0
            i32.store offset=3772
            i32.const 0
            local.get 10
            local.get 10
            call $strlen
            i32.wrap_i64
            local.get 0
            call $get_next_block_key
            i32.store offset=3776
            block  ;; label = @5
              i32.const 0
              i32.load offset=3772
              i32.const 0
              i32.load offset=3764
              i32.eq
              br_if 0 (;@5;)
              i32.const 3261
              i32.const 0
              call $printf
              br 1 (;@4;)
            end
            i32.const 0
            i32.const 0
            i32.store offset=3780
          end
          local.get 3
          local.get 3
          call $strlen
          i32.wrap_i64
          call $get_hash
          drop
          block  ;; label = @4
            local.get 2
            i32.load
            local.tee 0
            i32.const 4095
            i32.gt_u
            br_if 0 (;@4;)
            block  ;; label = @5
              block  ;; label = @6
                local.get 8
                i32.load8_u
                br_if 0 (;@6;)
                i64.const 0
                local.set 5
                br 1 (;@5;)
              end
              local.get 7
              i32.const 3804
              i32.add
              local.tee 10
              i32.load
              local.get 0
              i32.add
              local.get 8
              i32.load8_u
              i32.store8
              block  ;; label = @6
                local.get 8
                call $strlen
                local.tee 5
                i64.const 2
                i64.lt_u
                br_if 0 (;@6;)
                i64.const 1
                local.set 4
                i32.const 1
                local.set 0
                loop  ;; label = @7
                  local.get 10
                  i32.load
                  local.get 0
                  local.get 2
                  i32.load
                  i32.add
                  i32.add
                  local.get 8
                  local.get 0
                  i32.add
                  i32.load8_u
                  i32.store8
                  local.get 0
                  i32.const 1
                  i32.add
                  local.set 0
                  local.get 8
                  call $strlen
                  local.tee 5
                  local.get 4
                  i64.const 1
                  i64.add
                  local.tee 4
                  i64.gt_u
                  br_if 0 (;@7;)
                end
              end
              local.get 2
              i32.load
              local.set 0
            end
            local.get 2
            local.get 0
            local.get 5
            i32.wrap_i64
            i32.add
            local.tee 0
            i32.store
          end
          local.get 7
          i32.const 3804
          i32.add
          local.tee 12
          i32.load
          local.get 0
          i32.add
          i32.const 10
          i32.store8
          local.get 2
          local.get 2
          i32.load
          i32.const 1
          i32.add
          local.tee 0
          i32.store
          block  ;; label = @4
            local.get 7
            i32.const 3812
            i32.add
            local.tee 13
            i32.load
            i32.const 3
            i32.ne
            br_if 0 (;@4;)
            local.get 0
            i32.const 4095
            i32.gt_u
            br_if 0 (;@4;)
            i32.const 0
            local.get 0
            call $sgx_calc_sealed_data_size
            local.set 14
            local.get 12
            i32.load
            local.get 2
            i32.load
            call $seal_data
            local.set 10
            block  ;; label = @5
              local.get 14
              i32.const 1
              i32.lt_s
              br_if 0 (;@5;)
              local.get 14
              i64.extend_i32_u
              local.set 15
              i64.const 0
              local.set 4
              block  ;; label = @6
                local.get 14
                i32.const 8
                i32.lt_u
                br_if 0 (;@6;)
                block  ;; label = @7
                  local.get 1
                  i32.const 16
                  i32.add
                  local.get 10
                  local.get 15
                  i32.wrap_i64
                  local.tee 0
                  i32.add
                  i32.ge_u
                  br_if 0 (;@7;)
                  local.get 10
                  local.get 1
                  i32.const 16
                  i32.add
                  local.get 0
                  i32.add
                  i32.lt_u
                  br_if 1 (;@6;)
                end
                i64.const 0
                local.set 4
                block  ;; label = @7
                  local.get 14
                  i32.const 32
                  i32.lt_u
                  br_if 0 (;@7;)
                  local.get 15
                  i64.const 4294967264
                  i64.and
                  local.tee 4
                  i64.const -32
                  i64.add
                  local.tee 5
                  i64.const 5
                  i64.shr_u
                  i64.const 1
                  i64.add
                  local.tee 16
                  i64.const 3
                  i64.and
                  local.set 17
                  i64.const 0
                  local.set 11
                  block  ;; label = @8
                    local.get 5
                    i64.const 96
                    i64.lt_u
                    br_if 0 (;@8;)
                    i64.const 0
                    local.set 11
                    i64.const 0
                    local.get 16
                    i64.const 1152921504606846972
                    i64.and
                    i64.sub
                    local.set 5
                    i32.const 0
                    local.set 9
                    loop  ;; label = @9
                      local.get 1
                      i32.const 16
                      i32.add
                      local.get 9
                      i32.add
                      local.tee 0
                      local.get 10
                      local.get 9
                      i32.add
                      local.tee 8
                      i64.load offset=8 align=1
                      i64.store offset=8
                      local.get 0
                      local.get 8
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 24
                      i32.add
                      local.get 8
                      i32.const 24
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 16
                      i32.add
                      local.get 8
                      i32.const 16
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 56
                      i32.add
                      local.get 8
                      i32.const 56
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 48
                      i32.add
                      local.get 8
                      i32.const 48
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 40
                      i32.add
                      local.get 8
                      i32.const 40
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 32
                      i32.add
                      local.get 8
                      i32.const 32
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 88
                      i32.add
                      local.get 8
                      i32.const 88
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 80
                      i32.add
                      local.get 8
                      i32.const 80
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 72
                      i32.add
                      local.get 8
                      i32.const 72
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 64
                      i32.add
                      local.get 8
                      i32.const 64
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 120
                      i32.add
                      local.get 8
                      i32.const 120
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 112
                      i32.add
                      local.get 8
                      i32.const 112
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 104
                      i32.add
                      local.get 8
                      i32.const 104
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 96
                      i32.add
                      local.get 8
                      i32.const 96
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 9
                      i32.const 128
                      i32.add
                      local.set 9
                      local.get 11
                      i64.const 128
                      i64.add
                      local.set 11
                      local.get 5
                      i64.const 4
                      i64.add
                      local.tee 5
                      i64.const 0
                      i64.ne
                      br_if 0 (;@9;)
                    end
                  end
                  block  ;; label = @8
                    local.get 17
                    i64.eqz
                    br_if 0 (;@8;)
                    i64.const 0
                    local.get 17
                    i64.sub
                    local.set 5
                    local.get 10
                    local.get 11
                    i32.wrap_i64
                    local.tee 8
                    i32.add
                    local.set 0
                    local.get 1
                    i32.const 16
                    i32.add
                    local.get 8
                    i32.add
                    local.set 8
                    loop  ;; label = @9
                      local.get 8
                      local.get 0
                      i64.load offset=8 align=1
                      i64.store offset=8
                      local.get 8
                      local.get 0
                      i64.load align=1
                      i64.store
                      local.get 8
                      i32.const 24
                      i32.add
                      local.get 0
                      i32.const 24
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 8
                      i32.const 16
                      i32.add
                      local.get 0
                      i32.const 16
                      i32.add
                      i64.load align=1
                      i64.store
                      local.get 0
                      i32.const 32
                      i32.add
                      local.set 0
                      local.get 8
                      i32.const 32
                      i32.add
                      local.set 8
                      local.get 5
                      i64.const 1
                      i64.add
                      local.tee 11
                      local.get 5
                      i64.ge_u
                      local.set 9
                      local.get 11
                      local.set 5
                      local.get 9
                      br_if 0 (;@9;)
                    end
                  end
                  local.get 4
                  local.get 15
                  i64.eq
                  br_if 2 (;@5;)
                  local.get 15
                  i64.const 24
                  i64.and
                  i64.eqz
                  br_if 1 (;@6;)
                end
                local.get 10
                local.get 4
                i32.wrap_i64
                local.tee 8
                i32.add
                local.set 0
                local.get 4
                local.get 15
                i64.const 4294967288
                i64.and
                local.tee 5
                i64.sub
                local.set 4
                local.get 1
                i32.const 16
                i32.add
                local.get 8
                i32.add
                local.set 8
                loop  ;; label = @7
                  local.get 8
                  local.get 0
                  i64.load align=1
                  i64.store
                  local.get 0
                  i32.const 8
                  i32.add
                  local.set 0
                  local.get 8
                  i32.const 8
                  i32.add
                  local.set 8
                  local.get 4
                  i64.const 8
                  i64.add
                  local.tee 4
                  i64.const 0
                  i64.ne
                  br_if 0 (;@7;)
                end
                local.get 5
                local.set 4
                local.get 5
                local.get 15
                i64.eq
                br_if 1 (;@5;)
              end
              local.get 4
              i64.const -1
              i64.xor
              local.get 15
              i64.add
              local.set 11
              block  ;; label = @6
                local.get 15
                i64.const 3
                i64.and
                local.tee 5
                i64.eqz
                br_if 0 (;@6;)
                local.get 10
                local.get 4
                i32.wrap_i64
                local.tee 8
                i32.add
                local.set 0
                local.get 1
                i32.const 16
                i32.add
                local.get 8
                i32.add
                local.set 8
                loop  ;; label = @7
                  local.get 8
                  local.get 0
                  i32.load8_u
                  i32.store8
                  local.get 0
                  i32.const 1
                  i32.add
                  local.set 0
                  local.get 8
                  i32.const 1
                  i32.add
                  local.set 8
                  local.get 4
                  i64.const 1
                  i64.add
                  local.set 4
                  local.get 5
                  i64.const -1
                  i64.add
                  local.tee 5
                  i64.const 0
                  i64.ne
                  br_if 0 (;@7;)
                end
              end
              local.get 11
              i64.const 3
              i64.lt_u
              br_if 0 (;@5;)
              local.get 15
              local.get 4
              i64.sub
              local.set 5
              local.get 4
              i32.wrap_i64
              local.set 18
              local.get 1
              i32.const 16
              i32.add
              local.set 9
              loop  ;; label = @6
                local.get 9
                local.get 18
                i32.add
                local.tee 0
                local.get 10
                local.get 18
                i32.add
                local.tee 8
                i32.load8_u
                i32.store8
                local.get 0
                i32.const 1
                i32.add
                local.get 8
                i32.const 1
                i32.add
                i32.load8_u
                i32.store8
                local.get 0
                i32.const 2
                i32.add
                local.get 8
                i32.const 2
                i32.add
                i32.load8_u
                i32.store8
                local.get 0
                i32.const 3
                i32.add
                local.get 8
                i32.const 3
                i32.add
                i32.load8_u
                i32.store8
                local.get 10
                i32.const 4
                i32.add
                local.set 10
                local.get 9
                i32.const 4
                i32.add
                local.set 9
                local.get 5
                i64.const -4
                i64.add
                local.tee 5
                i64.eqz
                i32.eqz
                br_if 0 (;@6;)
              end
            end
            local.get 1
            i32.const 16
            i32.add
            local.get 14
            i32.add
            local.tee 0
            i32.const 2570
            i32.store16 align=1
            local.get 0
            i32.const 2
            i32.add
            i32.const 10
            i32.store8
            local.get 1
            i32.const 12
            i32.add
            local.get 1
            i32.const 16
            i32.add
            local.get 14
            i32.const 3
            i32.add
            local.get 7
            i32.const 3800
            i32.add
            i32.load
            call $ocall_write_sealed_data
            br_if 3 (;@1;)
            block  ;; label = @5
              local.get 2
              i32.load
              local.tee 0
              i32.eqz
              br_if 0 (;@5;)
              local.get 12
              i32.load
              i32.const 0
              local.get 0
              call $memset
              drop
            end
            local.get 13
            i32.const 0
            i32.store
            local.get 2
            i32.const 0
            i32.store
          end
          i32.const 0
          i32.load offset=4032
          local.set 0
        end
        local.get 6
        i64.const 1
        i64.add
        local.tee 6
        local.get 0
        i64.extend_i32_s
        i64.lt_s
        br_if 0 (;@2;)
      end
    end
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 1
      i32.load offset=242076
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 1
    i32.const 242080
    i32.add
    global.set $__stack_pointer)
  (func $sgx_verify_block_messages (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 4
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      call $verify_block_messages
      i32.store
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $verify_block_messages (type 15) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 204832
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i32.const 0
    i32.load
    i32.store offset=204828
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.const 12
      i32.add
      local.get 0
      i32.const 102416
      i32.add
      i32.const 102400
      local.get 0
      i32.const 8
      i32.add
      call $ocall_read_region_data
      br_if 0 (;@1;)
      local.get 0
      i32.load offset=12
      local.tee 1
      br_if 0 (;@1;)
      local.get 0
      i32.const 102400
      i32.store offset=4
      local.get 0
      i32.const 102416
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
      drop
      i32.const 2
      local.set 1
      local.get 0
      i32.const 102416
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
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=4
          br_if 0 (;@3;)
          i32.const 1
          local.set 1
          br 1 (;@2;)
        end
        local.get 0
        i32.const 16
        i32.add
        i32.const 1
        i32.or
        local.set 2
        i32.const 1
        local.set 1
        i32.const 0
        local.set 3
        loop  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              i32.const 0
              i32.load offset=3780
              local.tee 4
              br_if 0 (;@5;)
              i32.const 0
              i32.load offset=3760
              local.set 5
              local.get 5
              local.get 5
              call $strlen
              i32.wrap_i64
              i32.const 0
              call $get_next_message_key
              local.set 6
              br 1 (;@4;)
            end
            i32.const 0
            i32.load offset=4040
            local.set 5
            local.get 5
            local.get 5
            call $strlen
            i32.wrap_i64
            local.get 4
            call $get_next_message_key
            local.set 6
          end
          i32.const 0
          local.set 7
          i32.const 0
          local.get 6
          i32.store offset=4040
          i32.const 0
          i32.const 0
          i32.load offset=3780
          i32.const 1
          i32.add
          i32.store offset=3780
          i64.const 5
          call $malloc
          local.set 8
          i64.const 2048
          call $malloc
          local.set 9
          block  ;; label = @4
            local.get 0
            i32.const 16
            i32.add
            local.get 3
            i32.add
            i32.load8_u
            local.tee 4
            i32.const -48
            i32.add
            i32.const 255
            i32.and
            i32.const 9
            i32.gt_u
            br_if 0 (;@4;)
            local.get 2
            local.get 3
            i32.add
            local.set 10
            i32.const 0
            local.set 5
            loop  ;; label = @5
              local.get 9
              local.get 5
              i32.add
              local.get 4
              i32.store8
              local.get 8
              local.get 5
              i32.add
              local.get 4
              i32.store8
              local.get 10
              local.get 5
              i32.add
              local.set 4
              local.get 5
              i32.const 1
              i32.add
              local.tee 7
              local.set 5
              local.get 4
              i32.load8_u
              local.tee 4
              i32.const -48
              i32.add
              i32.const 255
              i32.and
              i32.const 10
              i32.lt_u
              br_if 0 (;@5;)
            end
            local.get 3
            local.get 7
            i32.add
            local.set 3
          end
          local.get 8
          call $atoi
          local.tee 8
          local.get 3
          i32.add
          local.set 4
          block  ;; label = @4
            local.get 8
            i32.const 1
            i32.lt_s
            br_if 0 (;@4;)
            local.get 9
            local.get 7
            i32.add
            local.get 0
            i32.const 16
            i32.add
            local.get 3
            i32.add
            local.get 4
            local.get 3
            i32.const 1
            i32.add
            local.tee 5
            local.get 4
            local.get 5
            i32.gt_s
            select
            local.get 3
            i32.sub
            call $memcpy
            drop
            local.get 7
            i64.extend_i32_u
            local.set 11
            block  ;; label = @5
              block  ;; label = @6
                local.get 3
                i64.extend_i32_s
                local.tee 12
                i64.const 1
                i64.add
                local.tee 13
                local.get 4
                i64.extend_i32_s
                local.tee 14
                local.get 13
                local.get 14
                i64.gt_s
                select
                local.get 12
                i64.sub
                local.tee 15
                i64.const 4
                i64.lt_u
                br_if 0 (;@6;)
                local.get 15
                i64.const -4
                i64.and
                local.tee 16
                i64.const -4
                i64.add
                local.tee 17
                i64.const 2
                i64.shr_u
                i64.const 1
                i64.add
                local.tee 18
                i64.const 7
                i64.and
                local.set 19
                i64.const 0
                local.set 13
                block  ;; label = @7
                  block  ;; label = @8
                    local.get 17
                    i64.const 28
                    i64.ge_u
                    br_if 0 (;@8;)
                    i64.const 0
                    local.set 17
                    i64.const 0
                    local.set 18
                    br 1 (;@7;)
                  end
                  i64.const 0
                  local.set 17
                  i64.const 0
                  local.get 18
                  i64.const 9223372036854775800
                  i64.and
                  i64.sub
                  local.set 20
                  i64.const 0
                  local.set 18
                  loop  ;; label = @8
                    local.get 17
                    i64.const 8
                    i64.add
                    local.set 17
                    local.get 11
                    i64.const 8
                    i64.add
                    local.set 11
                    local.get 18
                    i64.const 8
                    i64.add
                    local.set 18
                    local.get 13
                    i64.const 8
                    i64.add
                    local.set 13
                    local.get 20
                    i64.const 8
                    i64.add
                    local.tee 20
                    i64.const 0
                    i64.ne
                    br_if 0 (;@8;)
                  end
                end
                block  ;; label = @7
                  local.get 19
                  i64.eqz
                  br_if 0 (;@7;)
                  i64.const 0
                  local.get 19
                  i64.sub
                  local.set 20
                  loop  ;; label = @8
                    local.get 17
                    i64.const 1
                    i64.add
                    local.set 17
                    local.get 11
                    i64.const 1
                    i64.add
                    local.set 11
                    local.get 18
                    i64.const 1
                    i64.add
                    local.set 18
                    local.get 13
                    i64.const 1
                    i64.add
                    local.set 13
                    local.get 20
                    i64.const 1
                    i64.add
                    local.tee 19
                    local.get 20
                    i64.ge_u
                    local.set 5
                    local.get 19
                    local.set 20
                    local.get 5
                    br_if 0 (;@8;)
                  end
                end
                local.get 17
                local.get 11
                i64.add
                local.get 18
                local.get 13
                i64.add
                i64.add
                local.set 11
                local.get 15
                local.get 16
                i64.eq
                br_if 1 (;@5;)
                local.get 16
                local.get 12
                i64.add
                local.set 12
              end
              loop  ;; label = @6
                local.get 11
                i64.const 1
                i64.add
                local.set 11
                local.get 12
                i64.const 1
                i64.add
                local.tee 12
                local.get 14
                i64.lt_s
                br_if 0 (;@6;)
              end
            end
            local.get 11
            i32.wrap_i64
            local.set 7
          end
          local.get 4
          local.get 9
          local.get 7
          local.get 6
          call $get_mac
          local.tee 10
          call $strlen
          i32.wrap_i64
          local.tee 7
          i32.add
          local.set 5
          i64.const 35
          call $malloc
          local.set 9
          block  ;; label = @4
            local.get 7
            i32.const 1
            i32.lt_s
            br_if 0 (;@4;)
            local.get 9
            local.get 0
            i32.const 16
            i32.add
            local.get 4
            i32.add
            local.get 5
            local.get 4
            i32.const 1
            i32.add
            local.tee 4
            local.get 5
            local.get 4
            i32.gt_s
            select
            local.get 8
            i32.const -1
            i32.xor
            i32.add
            local.get 3
            i32.sub
            i32.const 1
            i32.add
            call $memcpy
            drop
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 1
              br_if 0 (;@5;)
              i32.const 0
              local.set 1
              br 1 (;@4;)
            end
            local.get 9
            local.get 10
            local.get 7
            call $compareHashValues
            i32.const 0
            i32.ne
            local.set 1
          end
          local.get 5
          i32.const 1
          i32.add
          local.tee 3
          local.get 0
          i32.load offset=4
          i32.lt_u
          br_if 0 (;@3;)
        end
      end
      block  ;; label = @2
        i32.const 0
        i32.load offset=3780
        i32.const 3
        i32.ne
        br_if 0 (;@2;)
        i32.const 3214
        i32.const 0
        call $printf
        block  ;; label = @3
          block  ;; label = @4
            i32.const 0
            i32.load offset=3760
            br_if 0 (;@4;)
            i32.const 100
            local.set 5
            i32.const 0
            i32.const 100
            i32.store offset=3764
            i32.const 0
            i32.const 0
            i32.load offset=3768
            local.tee 4
            i32.store offset=3760
            br 1 (;@3;)
          end
          i32.const 0
          i32.const 0
          i32.load offset=3776
          local.tee 4
          i32.store offset=3760
          i32.const 0
          i32.const 0
          i32.load offset=3764
          i32.const 1
          i32.add
          local.tee 5
          i32.store offset=3764
        end
        i32.const 0
        local.get 5
        i32.store offset=3772
        i32.const 0
        local.get 4
        local.get 4
        call $strlen
        i32.wrap_i64
        local.get 5
        call $get_next_block_key
        i32.store offset=3776
        block  ;; label = @3
          i32.const 0
          i32.load offset=3772
          i32.const 0
          i32.load offset=3764
          i32.eq
          br_if 0 (;@3;)
          i32.const 3261
          i32.const 0
          call $printf
          br 1 (;@2;)
        end
        i32.const 0
        i32.const 0
        i32.store offset=3780
      end
      i32.const 2410
      i32.const 2839
      local.get 1
      select
      i32.const 0
      call $printf
    end
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 0
      i32.load offset=204828
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 0
    i32.const 204832
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_generate_config (type 10) (param i32) (result i32)
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
      i32.const 0
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 3
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          local.get 0
          i64.load offset=8
          local.tee 4
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          local.get 4
          i64.eqz
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 4
            call $malloc
            local.tee 2
            br_if 0 (;@4;)
            i32.const 3
            return
          end
          i32.const 1
          local.set 5
          local.get 2
          local.get 4
          local.get 3
          local.get 4
          call $memcpy_s
          br_if 1 (;@2;)
          local.get 4
          i32.wrap_i64
          local.get 2
          i32.add
          i32.const -1
          i32.add
          i32.const 0
          i32.store8
          local.get 4
          local.get 2
          call $strlen
          i64.const 1
          i64.add
          i64.ne
          br_if 1 (;@2;)
        end
        local.get 2
        local.get 0
        i32.load offset=16
        call $generate_config
        i32.const 0
        local.set 5
        i32.const 0
        local.set 1
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 2
      call $free
      local.get 5
      local.set 1
    end
    local.get 1)
  (func $generate_config (type 16) (param i32 i32)
    (local i32 i32 i32 i32 i64 i64 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    i32.const 0
    local.set 3
    i32.const 0
    i32.load offset=4032
    local.set 4
    i32.const 3181
    i32.const 0
    call $printf
    local.get 4
    i32.const 24
    i32.mul
    local.tee 4
    i32.const 3792
    i32.add
    i64.const 64
    call $malloc
    i32.store
    local.get 4
    i32.const 3796
    i32.add
    i64.const 64
    call $malloc
    i32.store
    local.get 4
    i32.const 3800
    i32.add
    i64.const 64
    call $malloc
    i32.store
    i64.const 4096
    call $malloc
    local.set 5
    local.get 4
    i32.const 3808
    i32.add
    i64.const 0
    i64.store
    local.get 4
    i32.const 3804
    i32.add
    local.get 5
    i32.store
    i32.const 0
    i32.load offset=4032
    local.tee 4
    i64.extend_i32_s
    local.set 6
    block  ;; label = @1
      local.get 1
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      local.get 4
      i32.const 24
      i32.mul
      i32.const 3792
      i32.add
      local.set 5
      local.get 1
      i64.extend_i32_u
      local.set 7
      i32.const 0
      local.set 3
      loop  ;; label = @2
        local.get 0
        local.get 3
        i32.add
        i32.load8_u
        local.tee 4
        i32.const 46
        i32.eq
        br_if 1 (;@1;)
        local.get 5
        i32.load
        local.get 3
        i32.add
        local.get 4
        i32.store8
        local.get 3
        i32.const 1
        i32.add
        local.set 3
        local.get 7
        i64.const -1
        i64.add
        local.tee 7
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
      end
      i32.const 0
      local.set 3
    end
    local.get 6
    i32.wrap_i64
    local.set 8
    block  ;; label = @1
      local.get 3
      i32.const 1
      i32.add
      local.get 1
      i32.ge_s
      br_if 0 (;@1;)
      local.get 8
      i32.const 24
      i32.mul
      i32.const 3796
      i32.add
      local.set 9
      local.get 0
      local.get 3
      i32.add
      local.set 10
      local.get 3
      i32.const -1
      i32.xor
      local.get 1
      i32.add
      i64.extend_i32_u
      local.set 7
      i32.const 0
      local.set 4
      loop  ;; label = @2
        local.get 10
        local.get 4
        i32.add
        local.tee 5
        i32.const 2
        i32.add
        i32.load8_u
        i32.const 45
        i32.eq
        br_if 1 (;@1;)
        local.get 9
        i32.load
        local.get 4
        i32.add
        local.get 5
        i32.const 1
        i32.add
        i32.load8_u
        i32.store8
        local.get 4
        i32.const 1
        i32.add
        local.set 4
        local.get 7
        i64.const -1
        i64.add
        local.tee 7
        i64.const 0
        i64.ne
        br_if 0 (;@2;)
      end
    end
    local.get 8
    i32.const 24
    i32.mul
    i32.const 3800
    i32.add
    local.set 10
    i32.const 0
    local.set 4
    block  ;; label = @1
      local.get 3
      i32.const 2
      i32.add
      local.tee 3
      local.get 1
      i32.ge_s
      br_if 0 (;@1;)
      i32.const 0
      local.set 9
      i32.const 0
      local.set 4
      loop  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            block  ;; label = @5
              block  ;; label = @6
                local.get 0
                local.get 3
                i32.add
                i32.load8_u
                local.tee 5
                i32.const -32
                i32.add
                br_table 5 (;@1;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 1 (;@5;) 2 (;@4;) 0 (;@6;)
              end
              local.get 5
              br_table 4 (;@1;) 0 (;@5;) 0 (;@5;) 0 (;@5;) 0 (;@5;) 0 (;@5;) 0 (;@5;) 0 (;@5;) 0 (;@5;) 0 (;@5;) 4 (;@1;) 0 (;@5;)
            end
            local.get 9
            i32.const 1
            i32.ne
            br_if 1 (;@3;)
          end
          local.get 10
          i32.load
          local.get 4
          i32.add
          local.get 5
          i32.store8
          i32.const 1
          local.set 9
          local.get 4
          i32.const 1
          i32.add
          local.set 4
        end
        local.get 3
        i32.const 1
        i32.add
        local.tee 3
        local.get 1
        i32.lt_s
        br_if 0 (;@2;)
      end
    end
    local.get 10
    i32.load
    local.get 4
    i32.add
    i32.const 0
    i32.store8
    local.get 2
    local.get 10
    i32.load
    i32.store
    i32.const 3290
    local.get 2
    call $printf
    i32.const 0
    i32.const 0
    i32.load offset=4032
    i32.const 1
    i32.add
    i32.store offset=4032
    local.get 2
    i32.const 16
    i32.add
    global.set $__stack_pointer)
  (func $sgx_startup_phase (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $startup_phase
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $startup_phase (type 6)
    (local i32 i32)
    i32.const 3237
    i32.const 0
    call $printf
    i32.const 100
    local.set 0
    i32.const 0
    i32.const 100
    i32.store offset=3764
    i32.const 0
    i32.const 2439
    i32.store offset=3768
    i32.const 3214
    i32.const 0
    call $printf
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=3760
        br_if 0 (;@2;)
        i32.const 0
        i32.const 100
        i32.store offset=3764
        i32.const 0
        i32.const 0
        i32.load offset=3768
        local.tee 1
        i32.store offset=3760
        br 1 (;@1;)
      end
      i32.const 0
      i32.const 0
      i32.load offset=3776
      local.tee 1
      i32.store offset=3760
      i32.const 0
      i32.const 0
      i32.load offset=3764
      i32.const 1
      i32.add
      local.tee 0
      i32.store offset=3764
    end
    i32.const 0
    local.get 0
    i32.store offset=3772
    i32.const 0
    local.get 1
    local.get 1
    call $strlen
    i32.wrap_i64
    local.get 0
    call $get_next_block_key
    i32.store offset=3776
    block  ;; label = @1
      i32.const 0
      i32.load offset=3772
      i32.const 0
      i32.load offset=3764
      i32.eq
      br_if 0 (;@1;)
      i32.const 3261
      i32.const 0
      call $printf
      return
    end
    i32.const 0
    i32.const 0
    i32.store offset=3780)
  (func $sgx_reset_block_key (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $reset_block_key
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $reset_block_key (type 6)
    i32.const 0
    i32.const 0
    i32.store offset=3760)
  (func $sgx_ecall_type_char (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 1
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load8_s
      call $ecall_type_char
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_type_char (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i32.const 18
      i32.eq
      br_if 0 (;@1;)
      i32.const 2770
      i32.const 63
      i32.const 2650
      i32.const 3073
      call $__assert
    end)
  (func $sgx_ecall_type_int (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 4
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load
      call $ecall_type_int
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_type_int (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i32.const 1234
      i32.eq
      br_if 0 (;@1;)
      i32.const 2770
      i32.const 74
      i32.const 2515
      i32.const 3036
      call $__assert
    end)
  (func $sgx_ecall_type_float (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 4
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      f32.load
      call $ecall_type_float
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_type_float (type 17) (param f32)
    (local f32 f64)
    block  ;; label = @1
      local.get 0
      f32.const -0x1.348p+10 (;=-1234;)
      f32.add
      local.tee 1
      f64.promote_f32
      local.tee 2
      local.get 2
      f64.neg
      local.get 1
      f32.const 0x0p+0 (;=0;)
      f32.ge
      select
      local.get 0
      f32.const 0x1.348p+10 (;=1234;)
      f32.add
      local.tee 0
      f64.promote_f32
      local.tee 2
      local.get 2
      f64.neg
      local.get 0
      f32.const 0x0p+0 (;=0;)
      f32.ge
      select
      f64.const 0x1.b7cdfd9d7bdbbp-34 (;=1e-10;)
      f64.mul
      local.tee 2
      local.get 2
      f64.add
      f64.le
      br_if 0 (;@1;)
      i32.const 2770
      i32.const 85
      i32.const 2548
      i32.const 3340
      call $__assert
    end)
  (func $sgx_ecall_type_double (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      f64.load
      call $ecall_type_double
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_type_double (type 18) (param f64)
    (local f64)
    block  ;; label = @1
      local.get 0
      f64.const -0x1.34a456d5cfaadp+10 (;=-1234.57;)
      f64.add
      local.tee 1
      local.get 1
      f64.neg
      local.get 1
      f64.const 0x0p+0 (;=0;)
      f64.ge
      select
      local.get 0
      f64.const 0x1.34a456d5cfaadp+10 (;=1234.57;)
      f64.add
      local.tee 0
      local.get 0
      f64.neg
      local.get 0
      f64.const 0x0p+0 (;=0;)
      f64.ge
      select
      f64.const 0x1.b7cdfd9d7bdbbp-34 (;=1e-10;)
      f64.mul
      local.tee 0
      local.get 0
      f64.add
      f64.le
      br_if 0 (;@1;)
      i32.const 2770
      i32.const 96
      i32.const 2911
      i32.const 3303
      call $__assert
    end)
  (func $sgx_ecall_type_size_t (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.load
      call $ecall_type_size_t
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_type_size_t (type 19) (param i64)
    block  ;; label = @1
      local.get 0
      i64.const 12345678
      i64.eq
      br_if 0 (;@1;)
      i32.const 2770
      i32.const 107
      i32.const 2584
      i32.const 2964
      call $__assert
    end)
  (func $sgx_ecall_type_wchar_t (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 4
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load
      call $ecall_type_wchar_t
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_type_wchar_t (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i32.const 4660
      i32.eq
      br_if 0 (;@1;)
      i32.const 2770
      i32.const 118
      i32.const 2565
      i32.const 3013
      call $__assert
    end)
  (func $sgx_ecall_type_struct (type 10) (param i32) (result i32)
    (local i32)
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
      i32.load
      local.get 0
      i64.load offset=8
      call $ecall_type_struct
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_type_struct (type 20) (param i32 i64)
    block  ;; label = @1
      local.get 0
      i32.const 1234
      i32.eq
      br_if 0 (;@1;)
      i32.const 2770
      i32.const 129
      i32.const 2530
      i32.const 3048
      call $__assert
    end
    block  ;; label = @1
      local.get 1
      i64.const 5678
      i64.eq
      br_if 0 (;@1;)
      i32.const 2770
      i32.const 130
      i32.const 2530
      i32.const 2988
      call $__assert
    end)
  (func $sgx_ecall_type_enum_union (type 10) (param i32) (result i32)
    (local i32)
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
      i32.load
      local.get 0
      i32.load offset=8
      call $ecall_type_enum_union
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_type_enum_union (type 16) (param i32 i32)
    block  ;; label = @1
      local.get 1
      i64.const 8
      call $sgx_is_outside_enclave
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      local.get 1
      i32.const 2
      i32.store
      block  ;; label = @2
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2770
        i32.const 147
        i32.const 2802
        i32.const 3096
        call $__assert
      end
      return
    end
    call $abort
    unreachable)
  (func $sgx_ecall_pointer_user_check (type 10) (param i32) (result i32)
    (local i32)
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
      local.get 0
      i32.load offset=8
      local.get 0
      i64.load offset=16
      call $ecall_pointer_user_check
      i64.store
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_pointer_user_check (type 21) (param i32 i64) (result i64)
    (local i32 i32 i64 i32 i32 i64 i64 i64 i64 i64 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    i32.const 144
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    i32.const 0
    local.set 3
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=140
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        local.get 1
        call $sgx_is_outside_enclave
        i32.const 1
        i32.ne
        br_if 0 (;@2;)
        local.get 2
        i32.const 32
        i32.add
        local.get 1
        i64.const 100
        local.get 1
        i64.const 100
        i64.lt_u
        select
        local.tee 4
        i32.wrap_i64
        local.tee 5
        i32.add
        i32.const 0
        i64.const 0
        i64.const 100
        local.get 4
        i64.sub
        local.get 4
        i64.const 99
        i64.gt_u
        select
        i32.wrap_i64
        call $memset
        drop
        local.get 2
        i32.const 32
        i32.add
        local.get 0
        local.get 5
        call $memcpy
        drop
        local.get 2
        i32.const 32
        i32.add
        local.set 6
        local.get 1
        local.set 7
        block  ;; label = @3
          local.get 4
          i64.const 2
          i64.lt_u
          br_if 0 (;@3;)
          block  ;; label = @4
            block  ;; label = @5
              local.get 4
              i64.const -2
              i64.add
              local.tee 7
              i64.const 14
              i64.ge_u
              br_if 0 (;@5;)
              i32.const 0
              local.set 3
              local.get 2
              i32.const 32
              i32.add
              local.set 6
              local.get 4
              local.set 7
              br 1 (;@4;)
            end
            local.get 7
            i64.const 1
            i64.shr_u
            i64.const 1
            i64.add
            local.tee 8
            i64.const -8
            i64.and
            local.tee 9
            i64.const -8
            i64.add
            local.tee 7
            i64.const 3
            i64.shr_u
            i64.const 1
            i64.add
            local.tee 10
            i64.const 1
            i64.and
            local.set 11
            local.get 9
            i32.wrap_i64
            local.set 6
            block  ;; label = @5
              block  ;; label = @6
                local.get 7
                i64.eqz
                i32.eqz
                br_if 0 (;@6;)
                i32.const 0
                local.set 3
                i64.const 0
                local.set 7
                i32.const 0
                local.set 12
                i32.const 0
                local.set 13
                i32.const 0
                local.set 14
                i32.const 0
                local.set 15
                i32.const 0
                local.set 16
                i32.const 0
                local.set 17
                i32.const 0
                local.set 18
                br 1 (;@5;)
              end
              i64.const 0
              local.get 10
              i64.const 4611686018427387902
              i64.and
              i64.sub
              local.set 10
              i32.const 0
              local.set 3
              local.get 2
              i32.const 32
              i32.add
              local.set 5
              i64.const 0
              local.set 7
              i32.const 0
              local.set 12
              i32.const 0
              local.set 13
              i32.const 0
              local.set 14
              i32.const 0
              local.set 15
              i32.const 0
              local.set 16
              i32.const 0
              local.set 17
              i32.const 0
              local.set 18
              loop  ;; label = @6
                local.get 12
                local.get 5
                i32.load16_s offset=2
                i32.add
                local.get 5
                i32.const 18
                i32.add
                i32.load16_s
                i32.add
                local.set 12
                local.get 3
                local.get 5
                i32.load16_s
                i32.add
                local.get 5
                i32.const 16
                i32.add
                i32.load16_s
                i32.add
                local.set 3
                local.get 17
                local.get 5
                i32.const 12
                i32.add
                i32.load16_s
                i32.add
                local.get 5
                i32.const 28
                i32.add
                i32.load16_s
                i32.add
                local.set 17
                local.get 16
                local.get 5
                i32.const 10
                i32.add
                i32.load16_s
                i32.add
                local.get 5
                i32.const 26
                i32.add
                i32.load16_s
                i32.add
                local.set 16
                local.get 15
                local.get 5
                i32.const 8
                i32.add
                i32.load16_s
                i32.add
                local.get 5
                i32.const 24
                i32.add
                i32.load16_s
                i32.add
                local.set 15
                local.get 13
                local.get 5
                i32.load16_s offset=4
                i32.add
                local.get 5
                i32.const 20
                i32.add
                i32.load16_s
                i32.add
                local.set 13
                local.get 18
                local.get 5
                i32.const 14
                i32.add
                i32.load16_s
                i32.add
                local.get 5
                i32.const 30
                i32.add
                i32.load16_s
                i32.add
                local.set 18
                local.get 14
                local.get 5
                i32.const 6
                i32.add
                i32.load16_s
                i32.add
                local.get 5
                i32.const 22
                i32.add
                i32.load16_s
                i32.add
                local.set 14
                local.get 5
                i32.const 32
                i32.add
                local.set 5
                local.get 7
                i64.const 16
                i64.add
                local.set 7
                local.get 10
                i64.const 2
                i64.add
                local.tee 10
                i64.const 0
                i64.ne
                br_if 0 (;@6;)
              end
            end
            local.get 9
            i64.const 1
            i64.shl
            local.set 10
            local.get 6
            i32.const 1
            i32.shl
            local.set 6
            block  ;; label = @5
              local.get 11
              i64.eqz
              br_if 0 (;@5;)
              local.get 13
              local.get 2
              i32.const 32
              i32.add
              local.get 7
              i32.wrap_i64
              i32.const 1
              i32.shl
              i32.add
              local.tee 5
              i32.load16_s offset=4
              i32.add
              local.set 13
              local.get 12
              local.get 5
              i32.load16_s offset=2
              i32.add
              local.set 12
              local.get 3
              local.get 5
              i32.load16_s
              i32.add
              local.set 3
              local.get 14
              local.get 5
              i32.const 6
              i32.add
              i32.load16_s
              i32.add
              local.set 14
              local.get 18
              local.get 5
              i32.const 14
              i32.add
              i32.load16_s
              i32.add
              local.set 18
              local.get 17
              local.get 5
              i32.const 12
              i32.add
              i32.load16_s
              i32.add
              local.set 17
              local.get 16
              local.get 5
              i32.const 10
              i32.add
              i32.load16_s
              i32.add
              local.set 16
              local.get 15
              local.get 5
              i32.const 8
              i32.add
              i32.load16_s
              i32.add
              local.set 15
            end
            local.get 4
            local.get 10
            i64.sub
            local.set 7
            local.get 2
            i32.const 32
            i32.add
            local.get 6
            i32.add
            local.set 6
            local.get 15
            local.get 3
            i32.add
            local.get 17
            local.get 13
            i32.add
            i32.add
            local.get 16
            local.get 12
            i32.add
            local.get 18
            local.get 14
            i32.add
            i32.add
            i32.add
            local.set 3
            local.get 8
            local.get 9
            i64.eq
            br_if 1 (;@3;)
          end
          local.get 6
          local.set 5
          loop  ;; label = @4
            local.get 3
            local.get 5
            i32.load16_s
            i32.add
            local.set 3
            local.get 5
            i32.const 2
            i32.add
            local.tee 6
            local.set 5
            local.get 7
            i64.const -2
            i64.add
            local.tee 7
            i64.const 1
            i64.gt_u
            br_if 0 (;@4;)
          end
        end
        block  ;; label = @3
          local.get 7
          i64.const 1
          i64.ne
          br_if 0 (;@3;)
          local.get 3
          local.get 6
          i32.load8_s
          i32.add
          local.set 3
        end
        local.get 2
        i32.const 16
        i32.add
        local.get 3
        i32.const -1
        i32.xor
        i32.store
        local.get 2
        local.get 4
        i64.store offset=8
        local.get 2
        local.get 0
        i32.store
        i32.const 3373
        local.get 2
        call $printf
        local.get 0
        i32.const 2952
        local.get 1
        i64.const 12
        local.get 4
        i64.const 12
        i64.lt_u
        select
        i32.wrap_i64
        call $memcpy
        drop
        i32.const 0
        i32.load
        local.get 2
        i32.load offset=140
        i32.ne
        br_if 1 (;@1;)
        local.get 2
        i32.const 144
        i32.add
        global.set $__stack_pointer
        local.get 4
        return
      end
      call $abort
      unreachable
    end
    call $__stack_chk_fail
    unreachable)
  (func $sgx_ecall_pointer_in (type 10) (param i32) (result i32)
    (local i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i64.const 4
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          block  ;; label = @4
            i64.const 4
            call $malloc
            local.tee 2
            br_if 0 (;@4;)
            i32.const 3
            return
          end
          i32.const 1
          local.set 1
          local.get 2
          i64.const 4
          local.get 0
          i64.const 4
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 2
        call $ecall_pointer_in
        i32.const 0
        local.set 1
      end
      local.get 2
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      call $free
    end
    local.get 1)
  (func $ecall_pointer_in (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i64.const 4
      call $sgx_is_within_enclave
      i32.const 1
      i32.eq
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 0
    i32.const 1234
    i32.store)
  (func $sgx_ecall_pointer_out (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i64.const 4
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          i64.const 4
          call $malloc
          local.tee 1
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        call $ecall_pointer_out
        i32.const 0
        return
      end
      local.get 1
      i32.const 0
      i32.store
      local.get 1
      call $ecall_pointer_out
      local.get 0
      i64.const 4
      local.get 1
      i64.const 4
      call $memcpy_s
      local.set 0
      local.get 1
      call $free
      local.get 0
      i32.const 0
      i32.ne
      local.set 1
    end
    local.get 1)
  (func $ecall_pointer_out (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i64.const 4
      call $sgx_is_within_enclave
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 0
        i32.load
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2699
        i32.const 99
        i32.const 2478
        i32.const 3115
        call $__assert
      end
      local.get 0
      i32.const 1234
      i32.store
      return
    end
    call $abort
    unreachable)
  (func $sgx_ecall_pointer_in_out (type 10) (param i32) (result i32)
    (local i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i64.const 4
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          i64.const 4
          call $malloc
          local.tee 2
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        call $ecall_pointer_in_out
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 2
        i64.const 4
        local.get 0
        i64.const 4
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 2
        call $ecall_pointer_in_out
        local.get 0
        i64.const 4
        local.get 2
        i64.const 4
        call $memcpy_s
        i32.const 0
        i32.ne
        local.set 1
      end
      local.get 2
      call $free
    end
    local.get 1)
  (func $ecall_pointer_in_out (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i64.const 4
      call $sgx_is_within_enclave
      i32.const 1
      i32.eq
      br_if 0 (;@1;)
      call $abort
      unreachable
    end
    local.get 0
    i32.const 1234
    i32.store)
  (func $sgx_ecall_pointer_string (type 10) (param i32) (result i32)
    (local i32 i32 i64 i32)
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
          local.tee 4
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
          call $ecall_pointer_string
          local.get 4
          i32.const 0
          i32.store8
          local.get 2
          local.get 0
          call $strlen
          i64.const 1
          i64.add
          local.tee 3
          local.get 0
          local.get 3
          call $memcpy_s
          i32.const 0
          i32.ne
          local.set 1
        end
        local.get 0
        call $free
      end
      local.get 1
      return
    end
    i32.const 0
    call $ecall_pointer_string
    i32.const 0)
  (func $ecall_pointer_string (type 4) (param i32)
    local.get 0
    i32.const 3085
    local.get 0
    call $strlen
    call $strncpy
    drop)
  (func $sgx_ecall_pointer_string_const (type 10) (param i32) (result i32)
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
          call $ecall_pointer_string_const
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
    call $ecall_pointer_string_const
    i32.const 0)
  (func $ecall_pointer_string_const (type 4) (param i32))
  (func $sgx_ecall_pointer_size (type 10) (param i32) (result i32)
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
        call $ecall_pointer_size
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
        call $ecall_pointer_size
        local.get 0
        local.get 2
        local.get 3
        local.get 2
        call $memcpy_s
        i32.const 0
        i32.ne
        local.set 1
      end
      local.get 3
      call $free
    end
    local.get 1)
  (func $ecall_pointer_size (type 20) (param i32 i64)
    local.get 0
    i32.const 3085
    local.get 1
    call $strncpy
    drop)
  (func $sgx_ecall_pointer_count (type 10) (param i32) (result i32)
    (local i32 i32 i64 i32)
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
      i32.load offset=8
      local.tee 2
      i32.const 0
      i32.lt_s
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          local.get 2
          i64.extend_i32_s
          i64.const 2
          i64.shl
          local.tee 3
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          local.get 2
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          call $malloc
          local.tee 4
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        local.get 2
        call $ecall_pointer_count
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 4
        local.get 3
        local.get 0
        local.get 3
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 4
        local.get 2
        call $ecall_pointer_count
        local.get 0
        local.get 3
        local.get 4
        local.get 3
        call $memcpy_s
        i32.const 0
        i32.ne
        local.set 1
      end
      local.get 4
      call $free
    end
    local.get 1)
  (func $ecall_pointer_count (type 16) (param i32 i32)
    (local i32 i64 i32 i32 i32 i64 i64 i64 i64 i64 i32 i32 i32 i32)
    block  ;; label = @1
      local.get 1
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      local.get 1
      i32.const -1
      i32.add
      local.tee 2
      i64.extend_i32_u
      local.set 3
      block  ;; label = @2
        local.get 2
        i32.const 7
        i32.lt_u
        br_if 0 (;@2;)
        local.get 2
        i32.const -3
        i32.add
        local.set 4
        local.get 2
        i32.const -2
        i32.add
        local.set 5
        local.get 2
        i32.const -1
        i32.add
        local.set 6
        local.get 3
        i64.const 1
        i64.add
        local.tee 7
        i64.const 8589934584
        i64.and
        local.tee 8
        i64.const -8
        i64.add
        local.tee 9
        i64.const 3
        i64.shr_u
        i64.const 1
        i64.add
        local.tee 10
        i64.const 1
        i64.and
        local.set 11
        block  ;; label = @3
          block  ;; label = @4
            local.get 9
            i64.eqz
            i32.eqz
            br_if 0 (;@4;)
            i64.const 0
            local.set 9
            local.get 2
            local.set 12
            br 1 (;@3;)
          end
          i64.const 0
          local.get 10
          i64.const 4611686018427387902
          i64.and
          i64.sub
          local.set 10
          local.get 1
          i32.const 2
          i32.shl
          local.get 0
          i32.add
          i32.const -64
          i32.add
          local.set 13
          i64.const 0
          local.set 9
          local.get 2
          local.set 12
          loop  ;; label = @4
            local.get 13
            i32.const 60
            i32.add
            local.get 2
            local.get 12
            i32.sub
            local.tee 14
            i32.store
            local.get 13
            i32.const 44
            i32.add
            local.get 14
            i32.const 4
            i32.add
            i32.store
            local.get 13
            i32.const 56
            i32.add
            local.get 2
            local.get 6
            i32.sub
            local.tee 15
            i32.store
            local.get 13
            i32.const 28
            i32.add
            local.get 14
            i32.const 8
            i32.add
            i32.store
            local.get 13
            i32.const 12
            i32.add
            local.get 14
            i32.const 12
            i32.add
            i32.store
            local.get 13
            i32.const 40
            i32.add
            local.get 15
            i32.const 4
            i32.add
            i32.store
            local.get 13
            i32.const 52
            i32.add
            local.get 2
            local.get 5
            i32.sub
            local.tee 14
            i32.store
            local.get 13
            i32.const 24
            i32.add
            local.get 15
            i32.const 8
            i32.add
            i32.store
            local.get 13
            local.get 15
            i32.const 12
            i32.add
            i32.store offset=8
            local.get 13
            i32.const 36
            i32.add
            local.get 14
            i32.const 4
            i32.add
            i32.store
            local.get 13
            i32.const 48
            i32.add
            local.get 2
            local.get 4
            i32.sub
            local.tee 15
            i32.store
            local.get 13
            i32.const 20
            i32.add
            local.get 14
            i32.const 8
            i32.add
            i32.store
            local.get 13
            local.get 14
            i32.const 12
            i32.add
            i32.store offset=4
            local.get 13
            i32.const 32
            i32.add
            local.get 15
            i32.const 4
            i32.add
            i32.store
            local.get 13
            i32.const 16
            i32.add
            local.get 15
            i32.const 8
            i32.add
            i32.store
            local.get 13
            local.get 15
            i32.const 12
            i32.add
            i32.store
            local.get 12
            i32.const -16
            i32.add
            local.set 12
            local.get 13
            i32.const -64
            i32.add
            local.set 13
            local.get 9
            i64.const 16
            i64.add
            local.set 9
            local.get 6
            i32.const -16
            i32.add
            local.set 6
            local.get 5
            i32.const -16
            i32.add
            local.set 5
            local.get 4
            i32.const -16
            i32.add
            local.set 4
            local.get 10
            i64.const 2
            i64.add
            local.tee 10
            i64.const 0
            i64.ne
            br_if 0 (;@4;)
          end
        end
        block  ;; label = @3
          local.get 11
          i64.eqz
          br_if 0 (;@3;)
          local.get 0
          local.get 3
          local.get 9
          i64.sub
          i32.wrap_i64
          i32.const 2
          i32.shl
          i32.add
          local.tee 14
          local.get 2
          local.get 12
          i32.sub
          local.tee 15
          i32.store
          local.get 14
          i32.const -28
          i32.add
          local.tee 13
          local.get 2
          local.get 6
          i32.sub
          local.tee 6
          i32.const 4
          i32.add
          i32.store offset=8
          local.get 13
          local.get 2
          local.get 5
          i32.sub
          local.tee 5
          i32.const 4
          i32.add
          i32.store offset=4
          local.get 13
          local.get 2
          local.get 4
          i32.sub
          local.tee 4
          i32.const 4
          i32.add
          i32.store
          local.get 14
          i32.const -12
          i32.add
          local.tee 2
          local.get 6
          i32.store offset=8
          local.get 2
          local.get 5
          i32.store offset=4
          local.get 2
          local.get 4
          i32.store
          local.get 13
          i32.const 12
          i32.add
          local.get 15
          i32.const 4
          i32.add
          i32.store
        end
        local.get 7
        local.get 8
        i64.eq
        br_if 1 (;@1;)
        local.get 3
        local.get 8
        i64.sub
        local.set 3
      end
      local.get 3
      i64.const 1
      i64.add
      local.set 9
      local.get 0
      local.get 3
      i32.wrap_i64
      local.tee 2
      i32.const 2
      i32.shl
      i32.add
      local.set 13
      local.get 2
      i32.const -1
      i32.xor
      local.get 1
      i32.add
      local.set 2
      loop  ;; label = @2
        local.get 13
        local.get 2
        i32.store
        local.get 13
        i32.const -4
        i32.add
        local.set 13
        local.get 2
        i32.const 1
        i32.add
        local.set 2
        local.get 9
        i64.const -1
        i64.add
        local.tee 9
        i64.const 0
        i64.gt_s
        br_if 0 (;@2;)
      end
    end)
  (func $sgx_ecall_pointer_isptr_readonly (type 10) (param i32) (result i32)
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
        call $ecall_pointer_isptr_readonly
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
        call $ecall_pointer_isptr_readonly
        i32.const 0
        local.set 1
      end
      local.get 3
      call $free
    end
    local.get 1)
  (func $ecall_pointer_isptr_readonly (type 20) (param i32 i64)
    local.get 0
    i32.const 3085
    local.get 1
    call $strncpy
    drop)
  (func $sgx_ecall_pointer_sizefunc (type 10) (param i32) (result i32)
    (local i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i64.const 40
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          i64.const 40
          call $malloc
          local.tee 2
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        call $ecall_pointer_sizefunc
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 2
        i64.const 40
        local.get 0
        i64.const 40
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 2
        call $ecall_pointer_sizefunc
        local.get 0
        i64.const 40
        local.get 2
        i64.const 40
        call $memcpy_s
        i32.const 0
        i32.ne
        local.set 1
      end
      local.get 2
      call $free
    end
    local.get 1)
  (func $ecall_pointer_sizefunc (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i32.load
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 0
    i32.store
    block  ;; label = @1
      local.get 0
      i32.load offset=4
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 1
    i32.store offset=4
    block  ;; label = @1
      local.get 0
      i32.load offset=8
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 2
    i32.store offset=8
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 3
    i32.store offset=12
    block  ;; label = @1
      local.get 0
      i32.load offset=16
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 4
    i32.store offset=16
    block  ;; label = @1
      local.get 0
      i32.load offset=20
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 5
    i32.store offset=20
    block  ;; label = @1
      local.get 0
      i32.load offset=24
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 6
    i32.store offset=24
    block  ;; label = @1
      local.get 0
      i32.load offset=28
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 7
    i32.store offset=28
    block  ;; label = @1
      local.get 0
      i32.load offset=32
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 8
    i32.store offset=32
    block  ;; label = @1
      local.get 0
      i32.load offset=36
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2699
      i32.const 206
      i32.const 2929
      i32.const 3137
      call $__assert
    end
    local.get 0
    i32.const 9
    i32.store offset=36)
  (func $sgx_ocall_pointer_attr (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $ocall_pointer_attr
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ocall_pointer_attr (type 6)
    (local i32)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 0
    global.set $__stack_pointer
    local.get 0
    i32.const 0
    i32.store offset=12
    block  ;; label = @1
      local.get 0
      i32.const 12
      i32.add
      call $ocall_pointer_user_check
      br_if 0 (;@1;)
      local.get 0
      i32.const 0
      i32.store offset=12
      local.get 0
      i32.const 12
      i32.add
      call $ocall_pointer_in
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 0
        i32.load offset=12
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2699
        i32.const 129
        i32.const 2631
        i32.const 3116
        call $__assert
      end
      local.get 0
      i32.const 0
      i32.store offset=12
      local.get 0
      i32.const 12
      i32.add
      call $ocall_pointer_out
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 0
        i32.load offset=12
        i32.const 1234
        i32.eq
        br_if 0 (;@2;)
        i32.const 2699
        i32.const 135
        i32.const 2631
        i32.const 3036
        call $__assert
      end
      local.get 0
      i32.const 0
      i32.store offset=12
      local.get 0
      i32.const 12
      i32.add
      call $ocall_pointer_in_out
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 0
        i32.load offset=12
        i32.const 1234
        i32.eq
        br_if 0 (;@2;)
        i32.const 2699
        i32.const 141
        i32.const 2631
        i32.const 3036
        call $__assert
      end
      local.get 0
      i32.const 16
      i32.add
      global.set $__stack_pointer
      return
    end
    call $abort
    unreachable)
  (func $sgx_ecall_array_user_check (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load
      call $ecall_array_user_check
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_array_user_check (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i64.const 16
      call $sgx_is_outside_enclave
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 0
        i32.load
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 39
        i32.const 2876
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 3
      i32.store
      block  ;; label = @2
        local.get 0
        i32.load offset=4
        i32.const 1
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 39
        i32.const 2876
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 2
      i32.store offset=4
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        i32.const 2
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 39
        i32.const 2876
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 1
      i32.store offset=8
      block  ;; label = @2
        local.get 0
        i32.load offset=12
        i32.const 3
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 39
        i32.const 2876
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 0
      i32.store offset=12
      return
    end
    call $abort
    unreachable)
  (func $sgx_ecall_array_in (type 10) (param i32) (result i32)
    (local i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i64.const 16
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          block  ;; label = @4
            i64.const 16
            call $malloc
            local.tee 2
            br_if 0 (;@4;)
            i32.const 3
            return
          end
          i32.const 1
          local.set 1
          local.get 2
          i64.const 16
          local.get 0
          i64.const 16
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 2
        call $ecall_array_in
        i32.const 0
        local.set 1
      end
      local.get 2
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      call $free
    end
    local.get 1)
  (func $ecall_array_in (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i32.load
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 51
      i32.const 2824
      i32.const 2899
      call $__assert
    end
    local.get 0
    i32.const 3
    i32.store
    block  ;; label = @1
      local.get 0
      i32.load offset=4
      i32.const 1
      i32.eq
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 51
      i32.const 2824
      i32.const 2899
      call $__assert
    end
    local.get 0
    i32.const 2
    i32.store offset=4
    block  ;; label = @1
      local.get 0
      i32.load offset=8
      i32.const 2
      i32.eq
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 51
      i32.const 2824
      i32.const 2899
      call $__assert
    end
    local.get 0
    i32.const 1
    i32.store offset=8
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.const 3
      i32.eq
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 51
      i32.const 2824
      i32.const 2899
      call $__assert
    end
    local.get 0
    i32.const 0
    i32.store offset=12)
  (func $sgx_ecall_array_out (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i64.const 16
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          i64.const 16
          call $malloc
          local.tee 1
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        call $ecall_array_out
        i32.const 0
        return
      end
      local.get 1
      i64.const 0
      i64.store
      local.get 1
      i32.const 8
      i32.add
      i64.const 0
      i64.store
      local.get 1
      call $ecall_array_out
      local.get 0
      i64.const 16
      local.get 1
      i64.const 16
      call $memcpy_s
      local.set 0
      local.get 1
      call $free
      local.get 0
      i32.const 0
      i32.ne
      local.set 1
    end
    local.get 1)
  (func $ecall_array_out (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i32.load
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 64
      i32.const 2462
      i32.const 3125
      call $__assert
    end
    local.get 0
    i32.const 3
    i32.store
    block  ;; label = @1
      local.get 0
      i32.load offset=4
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 64
      i32.const 2462
      i32.const 3125
      call $__assert
    end
    local.get 0
    i32.const 2
    i32.store offset=4
    block  ;; label = @1
      local.get 0
      i32.load offset=8
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 64
      i32.const 2462
      i32.const 3125
      call $__assert
    end
    local.get 0
    i32.const 1
    i32.store offset=8
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 64
      i32.const 2462
      i32.const 3125
      call $__assert
    end
    local.get 0
    i32.const 0
    i32.store offset=12)
  (func $sgx_ecall_array_in_out (type 10) (param i32) (result i32)
    (local i32 i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 0
          i64.const 16
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          i64.const 16
          call $malloc
          local.tee 2
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        call $ecall_array_in_out
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 2
        i64.const 16
        local.get 0
        i64.const 16
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 2
        call $ecall_array_in_out
        local.get 0
        i64.const 16
        local.get 2
        i64.const 16
        call $memcpy_s
        i32.const 0
        i32.ne
        local.set 1
      end
      local.get 2
      call $free
    end
    local.get 1)
  (func $ecall_array_in_out (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i32.load
      i32.eqz
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 76
      i32.const 2496
      i32.const 2899
      call $__assert
    end
    local.get 0
    i32.const 3
    i32.store
    block  ;; label = @1
      local.get 0
      i32.load offset=4
      i32.const 1
      i32.eq
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 76
      i32.const 2496
      i32.const 2899
      call $__assert
    end
    local.get 0
    i32.const 2
    i32.store offset=4
    block  ;; label = @1
      local.get 0
      i32.load offset=8
      i32.const 2
      i32.eq
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 76
      i32.const 2496
      i32.const 2899
      call $__assert
    end
    local.get 0
    i32.const 1
    i32.store offset=8
    block  ;; label = @1
      local.get 0
      i32.load offset=12
      i32.const 3
      i32.eq
      br_if 0 (;@1;)
      i32.const 2666
      i32.const 76
      i32.const 2496
      i32.const 2899
      call $__assert
    end
    local.get 0
    i32.const 0
    i32.store offset=12)
  (func $sgx_ecall_array_isary (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i32.load
      call $ecall_array_isary
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_array_isary (type 4) (param i32)
    block  ;; label = @1
      local.get 0
      i64.const 40
      call $sgx_is_outside_enclave
      i32.const 1
      i32.ne
      br_if 0 (;@1;)
      block  ;; label = @2
        local.get 0
        i32.load
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 9
      i32.store
      block  ;; label = @2
        local.get 0
        i32.load offset=4
        i32.const 1
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 8
      i32.store offset=4
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        i32.const 2
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 7
      i32.store offset=8
      block  ;; label = @2
        local.get 0
        i32.load offset=12
        i32.const 3
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 6
      i32.store offset=12
      block  ;; label = @2
        local.get 0
        i32.load offset=16
        i32.const 4
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 5
      i32.store offset=16
      block  ;; label = @2
        local.get 0
        i32.load offset=20
        i32.const 5
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 4
      i32.store offset=20
      block  ;; label = @2
        local.get 0
        i32.load offset=24
        i32.const 6
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 3
      i32.store offset=24
      block  ;; label = @2
        local.get 0
        i32.load offset=28
        i32.const 7
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 2
      i32.store offset=28
      block  ;; label = @2
        local.get 0
        i32.load offset=32
        i32.const 8
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 1
      i32.store offset=32
      block  ;; label = @2
        local.get 0
        i32.load offset=36
        i32.const 9
        i32.eq
        br_if 0 (;@2;)
        i32.const 2666
        i32.const 91
        i32.const 2392
        i32.const 2899
        call $__assert
      end
      local.get 0
      i32.const 0
      i32.store offset=36
      return
    end
    call $abort
    unreachable)
  (func $sgx_ecall_function_calling_convs (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $ecall_function_calling_convs
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_function_calling_convs (type 6)
    i32.const 2734
    i32.const 50
    i32.const 2602
    i32.const 3149
    call $__assert)
  (func $sgx_ecall_function_public (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $ecall_function_public
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_function_public (type 6)
    block  ;; label = @1
      call $ocall_function_allow
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end)
  (func $sgx_ecall_function_private (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 4
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      call $ecall_function_private
      i32.store
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_function_private (type 15) (result i32)
    i32.const 1)
  (func $sgx_ecall_malloc_free (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $ecall_malloc_free
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_malloc_free (type 6))
  (func $sgx_ecall_sgx_cpuid (type 10) (param i32) (result i32)
    (local i32 i32 i32)
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
      i32.const 0
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load
          local.tee 3
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.const 16
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          block  ;; label = @4
            i64.const 16
            call $malloc
            local.tee 2
            br_if 0 (;@4;)
            i32.const 3
            return
          end
          i32.const 1
          local.set 1
          local.get 2
          i64.const 16
          local.get 3
          i64.const 16
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 2
        local.get 0
        i32.load offset=8
        call $ecall_sgx_cpuid
        i32.const 0
        local.set 1
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        i64.const 16
        local.get 2
        i64.const 16
        call $memcpy_s
        i32.const 0
        i32.ne
        local.set 1
      end
      local.get 2
      call $free
    end
    local.get 1)
  (func $ecall_sgx_cpuid (type 16) (param i32 i32)
    block  ;; label = @1
      local.get 0
      local.get 1
      call $sgx_cpuid
      i32.eqz
      br_if 0 (;@1;)
      call $abort
      unreachable
    end)
  (func $sgx_ecall_exception (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $ecall_exception
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_exception (type 6))
  (func $sgx_ecall_map (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $ecall_map
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_map (type 6))
  (func $sgx_ecall_increase_counter (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      i64.const 8
      call $sgx_is_outside_enclave
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      call $ecall_increase_counter
      i64.store
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_increase_counter (type 22) (result i64)
    (local i64 i32 i64)
    i64.const 0
    local.set 0
    i32.const 500
    local.set 1
    loop  ;; label = @1
      i32.const 3408
      call $sgx_thread_mutex_lock
      drop
      i32.const 0
      i32.const 0
      i64.load offset=4048
      i64.const 1
      i64.add
      local.tee 2
      i64.store offset=4048
      i32.const 3408
      call $sgx_thread_mutex_unlock
      drop
      i64.const 2000
      local.get 0
      local.get 2
      i64.const 2000
      i64.eq
      select
      local.set 0
      local.get 1
      i32.const -1
      i32.add
      local.tee 1
      br_if 0 (;@1;)
    end
    local.get 0)
  (func $sgx_ecall_producer (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $ecall_producer
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_producer (type 6)
    (local i32 i32)
    i32.const 0
    local.set 0
    loop  ;; label = @1
      i32.const 3664
      call $sgx_thread_mutex_lock
      drop
      block  ;; label = @2
        i32.const 0
        i32.load offset=3648
        i32.const 50
        i32.lt_s
        br_if 0 (;@2;)
        loop  ;; label = @3
          i32.const 3728
          i32.const 3664
          call $sgx_thread_cond_wait
          drop
          i32.const 0
          i32.load offset=3648
          i32.const 49
          i32.gt_s
          br_if 0 (;@3;)
        end
      end
      i32.const 0
      i32.load offset=3652
      local.tee 1
      i32.const 2
      i32.shl
      i32.const 3448
      i32.add
      local.get 1
      i32.store
      i32.const 0
      i32.const 0
      i32.load offset=3648
      i32.const 1
      i32.add
      i32.store offset=3648
      i32.const 0
      i32.const 0
      i32.load offset=3652
      i32.const 1
      i32.add
      i32.const 50
      i32.rem_s
      i32.store offset=3652
      i32.const 3704
      call $sgx_thread_cond_signal
      drop
      i32.const 3664
      call $sgx_thread_mutex_unlock
      drop
      local.get 0
      i32.const 1
      i32.add
      local.tee 0
      i32.const 2000
      i32.ne
      br_if 0 (;@1;)
    end)
  (func $sgx_ecall_consumer (type 10) (param i32) (result i32)
    (local i32)
    i32.const 2
    local.set 1
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      call $ecall_consumer
      i32.const 0
      local.set 1
    end
    local.get 1)
  (func $ecall_consumer (type 6)
    (local i32 i32)
    i32.const 0
    local.set 0
    loop  ;; label = @1
      i32.const 3664
      call $sgx_thread_mutex_lock
      drop
      block  ;; label = @2
        i32.const 0
        i32.load offset=3648
        i32.const 0
        i32.gt_s
        br_if 0 (;@2;)
        loop  ;; label = @3
          i32.const 3704
          i32.const 3664
          call $sgx_thread_cond_wait
          drop
          i32.const 0
          i32.load offset=3648
          i32.const 1
          i32.lt_s
          br_if 0 (;@3;)
        end
      end
      i32.const 0
      i32.const 0
      i32.load offset=3656
      local.tee 1
      i32.const 1
      i32.add
      i32.store offset=3656
      local.get 1
      i32.const 2
      i32.shl
      i32.const 3448
      i32.add
      i32.const 0
      i32.store
      i32.const 0
      i32.const 0
      i32.load offset=3656
      i32.const 50
      i32.rem_s
      i32.store offset=3656
      i32.const 0
      i32.const 0
      i32.load offset=3648
      i32.const -1
      i32.add
      i32.store offset=3648
      i32.const 3728
      call $sgx_thread_cond_signal
      drop
      i32.const 3664
      call $sgx_thread_mutex_unlock
      drop
      local.get 0
      i32.const 1
      i32.add
      local.tee 0
      i32.const 500
      i32.ne
      br_if 0 (;@1;)
    end)
  (func $sgx_get_next_block_key (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32)
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
      i32.const 0
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=8
          local.tee 3
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.const 1
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          block  ;; label = @4
            i64.const 1
            call $malloc
            local.tee 2
            br_if 0 (;@4;)
            i32.const 3
            return
          end
          i32.const 1
          local.set 4
          local.get 2
          i64.const 1
          local.get 3
          i64.const 1
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 0
        local.get 2
        local.get 0
        i32.load offset=16
        local.get 0
        i32.load offset=20
        call $get_next_block_key
        i32.store
        i32.const 0
        local.set 4
        i32.const 0
        local.set 1
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 2
      call $free
      local.get 4
      local.set 1
    end
    local.get 1)
  (func $get_next_block_key (type 7) (param i32 i32 i32) (result i32)
    (local i32 i32 i32 i64)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    i32.const 0
    local.set 4
    local.get 3
    i32.const 0
    i32.load
    i32.store offset=12
    local.get 2
    local.get 3
    i32.const 2
    i32.add
    i32.const 10
    call $itoa
    local.set 5
    i64.const 2048
    call $malloc
    local.set 2
    block  ;; label = @1
      local.get 1
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      local.get 2
      local.get 0
      local.get 1
      call $memcpy
      drop
      local.get 1
      local.set 4
    end
    block  ;; label = @1
      local.get 5
      call $strlen
      local.tee 6
      i64.eqz
      br_if 0 (;@1;)
      local.get 2
      local.get 4
      i32.add
      local.get 0
      local.get 6
      i32.wrap_i64
      local.tee 1
      call $memcpy
      drop
      local.get 4
      local.get 1
      i32.add
      local.set 4
    end
    local.get 2
    local.get 4
    i64.const 1000
    call $malloc
    local.tee 1
    call $sgx_sha256_msg
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 3
      i32.load offset=12
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 3
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_get_next_message_key (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32)
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
      i32.const 0
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=8
          local.tee 3
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.const 1
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          block  ;; label = @4
            i64.const 1
            call $malloc
            local.tee 2
            br_if 0 (;@4;)
            i32.const 3
            return
          end
          i32.const 1
          local.set 4
          local.get 2
          i64.const 1
          local.get 3
          i64.const 1
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 0
        local.get 2
        local.get 0
        i32.load offset=16
        local.get 0
        i32.load offset=20
        call $get_next_message_key
        i32.store
        i32.const 0
        local.set 4
        i32.const 0
        local.set 1
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 2
      call $free
      local.get 4
      local.set 1
    end
    local.get 1)
  (func $get_next_message_key (type 7) (param i32 i32 i32) (result i32)
    (local i32 i32 i32 i64)
    global.get $__stack_pointer
    i32.const 16
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    i32.const 0
    local.set 4
    local.get 3
    i32.const 0
    i32.load
    i32.store offset=12
    local.get 2
    local.get 3
    i32.const 2
    i32.add
    i32.const 10
    call $itoa
    local.set 5
    i64.const 2048
    call $malloc
    local.set 2
    block  ;; label = @1
      local.get 1
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      local.get 2
      local.get 0
      local.get 1
      call $memcpy
      drop
      local.get 1
      local.set 4
    end
    block  ;; label = @1
      local.get 5
      call $strlen
      local.tee 6
      i64.eqz
      br_if 0 (;@1;)
      local.get 2
      local.get 4
      i32.add
      local.get 0
      local.get 6
      i32.wrap_i64
      local.tee 1
      call $memcpy
      drop
      local.get 4
      local.get 1
      i32.add
      local.set 4
    end
    local.get 2
    local.get 4
    i64.const 1000
    call $malloc
    local.tee 1
    call $sgx_sha256_msg
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 3
      i32.load offset=12
      i32.eq
      br_if 0 (;@1;)
      call $__stack_chk_fail
      unreachable
    end
    local.get 3
    i32.const 16
    i32.add
    global.set $__stack_pointer
    local.get 1)
  (func $sgx_get_mac (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32 i32)
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
      i32.load offset=24
      local.set 2
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        local.tee 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i64.const 1
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i64.const 1
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 4
      i32.const 0
      local.set 5
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 3
            i32.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              i64.const 1
              call $malloc
              local.tee 5
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 5
            i64.const 1
            local.get 3
            i64.const 1
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 1
            i32.const 0
            local.set 4
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.eqz
              br_if 0 (;@5;)
              block  ;; label = @6
                i64.const 1
                call $malloc
                local.tee 4
                br_if 0 (;@6;)
                i32.const 0
                local.set 4
                i32.const 3
                local.set 1
                br 2 (;@4;)
              end
              i32.const 1
              local.set 1
              local.get 4
              i64.const 1
              local.get 2
              i64.const 1
              call $memcpy_s
              br_if 1 (;@4;)
            end
            local.get 0
            local.get 5
            local.get 0
            i32.load offset=16
            local.get 4
            call $get_mac
            i32.store
            i32.const 0
            local.set 1
          end
          local.get 5
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 5
        call $free
      end
      local.get 4
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      call $free
    end
    local.get 1)
  (func $get_mac (type 7) (param i32 i32 i32) (result i32)
    (local i32)
    i64.const 16
    call $malloc
    local.tee 3
    i32.const 8
    i32.add
    local.get 2
    i32.const 8
    i32.add
    i64.load align=1
    i64.store align=1
    local.get 3
    local.get 2
    i64.load align=1
    i64.store align=1
    local.get 3
    local.get 0
    local.get 1
    i64.const 1000
    call $malloc
    local.tee 2
    call $sgx_rijndael128_cmac_msg
    drop
    local.get 2)
  (func $sgx_hash (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32)
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
      i32.const 0
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=8
          local.tee 3
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.const 1
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          block  ;; label = @4
            i64.const 1
            call $malloc
            local.tee 2
            br_if 0 (;@4;)
            i32.const 3
            return
          end
          i32.const 1
          local.set 4
          local.get 2
          i64.const 1
          local.get 3
          i64.const 1
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 0
        local.get 2
        local.get 0
        i32.load offset=16
        call $hash
        i32.store
        i32.const 0
        local.set 4
        i32.const 0
        local.set 1
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 2
      call $free
      local.get 4
      local.set 1
    end
    local.get 1)
  (func $hash (type 5) (param i32 i32) (result i32)
    (local i32)
    local.get 0
    local.get 1
    i64.const 1000
    call $malloc
    local.tee 2
    call $sgx_sha256_msg
    drop
    local.get 2)
  (func $sgx_compareHashValues (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32 i32)
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
      i32.load offset=16
      local.set 2
      block  ;; label = @2
        local.get 0
        i32.load offset=8
        local.tee 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i64.const 1
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i64.const 1
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 4
      i32.const 0
      local.set 5
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 3
            i32.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              i64.const 1
              call $malloc
              local.tee 5
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 5
            i64.const 1
            local.get 3
            i64.const 1
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 1
            i32.const 0
            local.set 4
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.eqz
              br_if 0 (;@5;)
              block  ;; label = @6
                i64.const 1
                call $malloc
                local.tee 4
                br_if 0 (;@6;)
                i32.const 0
                local.set 4
                i32.const 3
                local.set 1
                br 2 (;@4;)
              end
              i32.const 1
              local.set 1
              local.get 4
              i64.const 1
              local.get 2
              i64.const 1
              call $memcpy_s
              br_if 1 (;@4;)
            end
            local.get 0
            local.get 5
            local.get 4
            local.get 0
            i32.load offset=24
            call $compareHashValues
            i32.store
            i32.const 0
            local.set 1
          end
          local.get 5
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 5
        call $free
      end
      local.get 4
      i32.eqz
      br_if 0 (;@1;)
      local.get 4
      call $free
    end
    local.get 1)
  (func $compareHashValues (type 7) (param i32 i32 i32) (result i32)
    (local i32 i32 i64 i64 i64)
    global.get $__stack_pointer
    i32.const 32
    i32.sub
    local.tee 3
    global.set $__stack_pointer
    i32.const 1
    local.set 4
    block  ;; label = @1
      local.get 2
      i32.const 1
      i32.lt_s
      br_if 0 (;@1;)
      local.get 0
      i32.load8_s
      local.set 4
      local.get 3
      local.get 1
      i32.load8_s
      i32.store offset=20
      local.get 3
      local.get 4
      i32.store offset=16
      i32.const 2455
      local.get 3
      i32.const 16
      i32.add
      call $printf
      i32.const 0
      local.set 4
      local.get 0
      i32.load8_u
      local.get 1
      i32.load8_u
      i32.ne
      br_if 0 (;@1;)
      local.get 2
      i64.extend_i32_u
      local.set 5
      local.get 0
      i32.const 1
      i32.add
      local.set 4
      local.get 1
      i32.const 1
      i32.add
      local.set 0
      i64.const 1
      local.set 6
      block  ;; label = @2
        loop  ;; label = @3
          local.get 5
          local.get 6
          local.tee 7
          i64.eq
          br_if 1 (;@2;)
          local.get 4
          i32.load8_s
          local.set 1
          local.get 3
          local.get 0
          i32.load8_s
          i32.store offset=4
          local.get 3
          local.get 1
          i32.store
          i32.const 2455
          local.get 3
          call $printf
          local.get 7
          i64.const 1
          i64.add
          local.set 6
          local.get 0
          i32.load8_u
          local.set 1
          local.get 4
          i32.load8_u
          local.set 2
          local.get 4
          i32.const 1
          i32.add
          local.set 4
          local.get 0
          i32.const 1
          i32.add
          local.set 0
          local.get 2
          local.get 1
          i32.eq
          br_if 0 (;@3;)
        end
      end
      local.get 7
      local.get 5
      i64.ge_u
      local.set 4
    end
    local.get 3
    i32.const 32
    i32.add
    global.set $__stack_pointer
    local.get 4)
  (func $sgx_reverse (type 10) (param i32) (result i32)
    (local i32 i32 i64 i32)
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
      i32.load offset=8
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
          i64.extend_i32_s
          local.tee 3
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          local.get 2
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          call $malloc
          local.tee 4
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        i32.const 0
        local.get 2
        call $reverse
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 4
        local.get 3
        local.get 0
        local.get 3
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 4
        local.get 2
        call $reverse
        i32.const 0
        local.set 1
      end
      local.get 4
      call $free
    end
    local.get 1)
  (func $reverse (type 16) (param i32 i32)
    (local i32 i64 i64)
    block  ;; label = @1
      local.get 1
      i32.const 2
      i32.lt_s
      br_if 0 (;@1;)
      local.get 1
      local.get 0
      i32.add
      i32.const -1
      i32.add
      local.set 2
      local.get 1
      i64.extend_i32_u
      i64.const -2
      i64.add
      local.set 3
      i64.const 0
      local.set 4
      loop  ;; label = @2
        local.get 0
        i32.load8_u
        local.set 1
        local.get 0
        local.get 2
        i32.load8_u
        i32.store8
        local.get 2
        local.get 1
        i32.store8
        local.get 2
        i32.const -1
        i32.add
        local.set 2
        local.get 0
        i32.const 1
        i32.add
        local.set 0
        local.get 4
        i64.const 1
        i64.add
        local.tee 4
        local.get 3
        i64.lt_s
        local.set 1
        local.get 3
        i64.const -1
        i64.add
        local.set 3
        local.get 1
        br_if 0 (;@2;)
      end
    end)
  (func $sgx_itoa (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32)
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
      i32.const 0
      local.set 2
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=16
          local.tee 3
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i64.const 1
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          block  ;; label = @4
            i64.const 1
            call $malloc
            local.tee 2
            br_if 0 (;@4;)
            i32.const 3
            return
          end
          i32.const 1
          local.set 4
          local.get 2
          i64.const 1
          local.get 3
          i64.const 1
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 0
        local.get 0
        i32.load offset=8
        local.get 2
        local.get 0
        i32.load offset=24
        call $itoa
        local.tee 2
        i32.store
        i32.const 0
        local.set 4
        i32.const 0
        local.set 1
        local.get 2
        i32.eqz
        br_if 1 (;@1;)
      end
      local.get 2
      call $free
      local.get 4
      local.set 1
    end
    local.get 1)
  (func $itoa (type 7) (param i32 i32 i32) (result i32)
    (local i32 i32 i32 i64 i64)
    block  ;; label = @1
      local.get 0
      br_if 0 (;@1;)
      local.get 1
      i32.const 48
      i32.store16 align=1
      local.get 1
      return
    end
    i32.const 0
    local.set 3
    block  ;; label = @1
      i32.const 0
      local.get 0
      i32.sub
      local.get 0
      local.get 0
      i32.const 0
      i32.lt_s
      local.get 2
      i32.const 10
      i32.eq
      i32.and
      local.tee 4
      select
      local.tee 0
      i32.eqz
      br_if 0 (;@1;)
      i32.const 0
      local.set 3
      loop  ;; label = @2
        local.get 1
        local.get 3
        i32.add
        i32.const 87
        i32.const 48
        local.get 0
        local.get 2
        i32.rem_s
        local.tee 5
        i32.const 9
        i32.gt_s
        select
        local.get 5
        i32.add
        i32.store8
        local.get 3
        i32.const 1
        i32.add
        local.set 3
        local.get 0
        local.get 2
        i32.div_s
        local.tee 0
        br_if 0 (;@2;)
      end
    end
    block  ;; label = @1
      local.get 4
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      local.get 3
      i32.add
      i32.const 45
      i32.store8
      local.get 3
      i32.const 1
      i32.add
      local.set 3
    end
    local.get 1
    local.get 3
    i32.add
    local.tee 0
    i32.const 0
    i32.store8
    block  ;; label = @1
      local.get 3
      i32.const 2
      i32.lt_s
      br_if 0 (;@1;)
      local.get 0
      i32.const -1
      i32.add
      local.set 0
      local.get 3
      i64.extend_i32_u
      i64.const -2
      i64.add
      local.set 6
      i64.const 0
      local.set 7
      local.get 1
      local.set 3
      loop  ;; label = @2
        local.get 3
        i32.load8_u
        local.set 2
        local.get 3
        local.get 0
        i32.load8_u
        i32.store8
        local.get 0
        local.get 2
        i32.store8
        local.get 0
        i32.const -1
        i32.add
        local.set 0
        local.get 3
        i32.const 1
        i32.add
        local.set 3
        local.get 7
        i64.const 1
        i64.add
        local.tee 7
        local.get 6
        i64.lt_s
        local.set 2
        local.get 6
        i64.const -1
        i64.add
        local.set 6
        local.get 2
        br_if 0 (;@2;)
      end
    end
    local.get 1)
  (func $sgx_myAtoi (type 10) (param i32) (result i32)
    (local i32 i32 i32)
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
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.load offset=8
          local.tee 2
          i32.eqz
          br_if 0 (;@3;)
          local.get 2
          i64.const 1
          call $sgx_is_outside_enclave
          i32.eqz
          br_if 2 (;@1;)
          i64.const 1
          call $malloc
          local.tee 3
          br_if 1 (;@2;)
          i32.const 3
          return
        end
        local.get 0
        i32.const 0
        call $myAtoi
        i32.store
        i32.const 0
        return
      end
      i32.const 1
      local.set 1
      block  ;; label = @2
        local.get 3
        i64.const 1
        local.get 2
        i64.const 1
        call $memcpy_s
        br_if 0 (;@2;)
        local.get 0
        local.get 3
        call $myAtoi
        i32.store
        i32.const 0
        local.set 1
      end
      local.get 3
      call $free
    end
    local.get 1)
  (func $myAtoi (type 10) (param i32) (result i32)
    (local i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        i32.load8_u
        local.tee 1
        br_if 0 (;@2;)
        i32.const 0
        local.set 2
        br 1 (;@1;)
      end
      local.get 0
      i32.const 1
      i32.add
      local.set 0
      i32.const 0
      local.set 2
      loop  ;; label = @2
        local.get 2
        i32.const 10
        i32.mul
        local.get 1
        i32.const 24
        i32.shl
        i32.const 24
        i32.shr_s
        i32.add
        i32.const -48
        i32.add
        local.set 2
        local.get 0
        i32.load8_u
        local.set 1
        local.get 0
        i32.const 1
        i32.add
        local.set 0
        local.get 1
        br_if 0 (;@2;)
      end
    end
    local.get 2)
  (func $sgx_get_hash (type 10) (param i32) (result i32)
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
          i64.extend_i32_s
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
        call $get_hash
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
        call $get_hash
        i32.store
        i32.const 0
        local.set 1
      end
      local.get 5
      call $free
    end
    local.get 1)
  (func $get_hash (type 5) (param i32 i32) (result i32)
    (local i32)
    local.get 0
    local.get 1
    i64.const 1000
    call $malloc
    local.tee 2
    call $sgx_sha256_msg
    drop
    local.get 2)
  (func $sgx_seal_data.124 (type 10) (param i32) (result i32)
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
        call $seal_data
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
        call $seal_data
        i32.store
        i32.const 0
        local.set 1
      end
      local.get 5
      call $free
    end
    local.get 1)
  (func $seal_data (type 5) (param i32 i32) (result i32)
    (local i32 i32 i32)
    i32.const 0
    local.set 2
    i64.const 20480
    call $malloc
    local.set 3
    block  ;; label = @1
      i32.const 0
      local.get 1
      call $sgx_calc_sealed_data_size
      local.tee 4
      i32.const 20408
      i32.gt_s
      br_if 0 (;@1;)
      i32.const 0
      local.get 3
      i32.const 0
      i32.const 0
      local.get 1
      local.get 0
      local.get 4
      local.get 3
      call $sgx_seal_data
      select
      local.set 2
    end
    local.get 2)
  (func $sgx_seal_and_write (type 10) (param i32) (result i32)
    (local i32 i32 i32 i32)
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
      i32.load offset=8
      local.set 2
      block  ;; label = @2
        local.get 0
        i32.load
        local.tee 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i64.const 1
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      block  ;; label = @2
        local.get 2
        i32.eqz
        br_if 0 (;@2;)
        local.get 2
        i64.const 1
        call $sgx_is_outside_enclave
        i32.eqz
        br_if 1 (;@1;)
      end
      i32.const 0
      local.set 3
      i32.const 0
      local.set 4
      block  ;; label = @2
        block  ;; label = @3
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            block  ;; label = @5
              i64.const 1
              call $malloc
              local.tee 4
              br_if 0 (;@5;)
              i32.const 3
              return
            end
            local.get 4
            i64.const 1
            local.get 0
            i64.const 1
            call $memcpy_s
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 1
            i32.const 0
            local.set 3
            br 1 (;@3;)
          end
          block  ;; label = @4
            block  ;; label = @5
              local.get 2
              i32.eqz
              br_if 0 (;@5;)
              block  ;; label = @6
                i64.const 1
                call $malloc
                local.tee 3
                br_if 0 (;@6;)
                i32.const 0
                local.set 3
                i32.const 3
                local.set 1
                br 2 (;@4;)
              end
              i32.const 1
              local.set 1
              local.get 3
              i64.const 1
              local.get 2
              i64.const 1
              call $memcpy_s
              br_if 1 (;@4;)
            end
            local.get 4
            local.get 3
            call $seal_and_write
            i32.const 0
            local.set 1
          end
          local.get 4
          i32.eqz
          br_if 1 (;@2;)
        end
        local.get 4
        call $free
      end
      local.get 3
      i32.eqz
      br_if 0 (;@1;)
      local.get 3
      call $free
    end
    local.get 1)
  (func $seal_and_write (type 16) (param i32 i32)
    (local i32 i32 i32 i32 i64 i64 i64 i64 i64 i64 i32 i32)
    global.get $__stack_pointer
    i32.const 24032
    i32.sub
    local.tee 2
    global.set $__stack_pointer
    local.get 2
    i32.const 0
    i32.load
    i32.store offset=24028
    i32.const 0
    local.get 0
    call $strlen
    i32.wrap_i64
    call $sgx_calc_sealed_data_size
    local.set 3
    local.get 0
    local.get 0
    call $strlen
    i32.wrap_i64
    i32.const 255
    i32.and
    call $seal_data
    local.set 4
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        i32.const 255
        i32.and
        local.tee 5
        br_if 0 (;@2;)
        i64.const 0
        local.set 6
        br 1 (;@1;)
      end
      local.get 5
      i64.extend_i32_u
      local.set 6
      i64.const 0
      local.set 7
      block  ;; label = @2
        local.get 5
        i32.const 8
        i32.lt_u
        br_if 0 (;@2;)
        block  ;; label = @3
          local.get 2
          i32.const 16
          i32.add
          local.get 4
          local.get 6
          i32.wrap_i64
          local.tee 0
          i32.add
          i32.ge_u
          br_if 0 (;@3;)
          local.get 4
          local.get 2
          i32.const 16
          i32.add
          local.get 0
          i32.add
          i32.lt_u
          br_if 1 (;@2;)
        end
        i64.const 0
        local.set 7
        block  ;; label = @3
          local.get 5
          i32.const 32
          i32.lt_u
          br_if 0 (;@3;)
          local.get 6
          i64.const 224
          i64.and
          local.tee 7
          i64.const -32
          i64.add
          local.tee 8
          i64.const 5
          i64.shr_u
          i64.const 1
          i64.add
          local.tee 9
          i64.const 3
          i64.and
          local.set 10
          i64.const 0
          local.set 11
          block  ;; label = @4
            local.get 8
            i64.const 96
            i64.lt_u
            br_if 0 (;@4;)
            i64.const 0
            local.get 9
            i64.const 1152921504606846972
            i64.and
            i64.sub
            local.set 8
            i32.const 0
            local.set 12
            i64.const 0
            local.set 11
            loop  ;; label = @5
              local.get 2
              i32.const 16
              i32.add
              local.get 12
              i32.add
              local.tee 0
              local.get 4
              local.get 12
              i32.add
              local.tee 3
              i64.load offset=8 align=1
              i64.store offset=8
              local.get 0
              local.get 3
              i64.load align=1
              i64.store
              local.get 0
              i32.const 24
              i32.add
              local.get 3
              i32.const 24
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 16
              i32.add
              local.get 3
              i32.const 16
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 56
              i32.add
              local.get 3
              i32.const 56
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 48
              i32.add
              local.get 3
              i32.const 48
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 40
              i32.add
              local.get 3
              i32.const 40
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 32
              i32.add
              local.get 3
              i32.const 32
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 88
              i32.add
              local.get 3
              i32.const 88
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 80
              i32.add
              local.get 3
              i32.const 80
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 72
              i32.add
              local.get 3
              i32.const 72
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 64
              i32.add
              local.get 3
              i32.const 64
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 120
              i32.add
              local.get 3
              i32.const 120
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 112
              i32.add
              local.get 3
              i32.const 112
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 104
              i32.add
              local.get 3
              i32.const 104
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 96
              i32.add
              local.get 3
              i32.const 96
              i32.add
              i64.load align=1
              i64.store
              local.get 12
              i32.const 128
              i32.add
              local.set 12
              local.get 11
              i64.const 128
              i64.add
              local.set 11
              local.get 8
              i64.const 4
              i64.add
              local.tee 8
              i64.const 0
              i64.ne
              br_if 0 (;@5;)
            end
          end
          block  ;; label = @4
            local.get 10
            i64.eqz
            br_if 0 (;@4;)
            i64.const 0
            local.get 10
            i64.sub
            local.set 8
            local.get 4
            local.get 11
            i32.wrap_i64
            local.tee 3
            i32.add
            local.set 0
            local.get 2
            i32.const 16
            i32.add
            local.get 3
            i32.add
            local.set 3
            loop  ;; label = @5
              local.get 3
              local.get 0
              i64.load offset=8 align=1
              i64.store offset=8
              local.get 3
              local.get 0
              i64.load align=1
              i64.store
              local.get 3
              i32.const 24
              i32.add
              local.get 0
              i32.const 24
              i32.add
              i64.load align=1
              i64.store
              local.get 3
              i32.const 16
              i32.add
              local.get 0
              i32.const 16
              i32.add
              i64.load align=1
              i64.store
              local.get 0
              i32.const 32
              i32.add
              local.set 0
              local.get 3
              i32.const 32
              i32.add
              local.set 3
              local.get 8
              i64.const 1
              i64.add
              local.tee 11
              local.get 8
              i64.ge_u
              local.set 12
              local.get 11
              local.set 8
              local.get 12
              br_if 0 (;@5;)
            end
          end
          local.get 7
          local.get 6
          i64.eq
          br_if 2 (;@1;)
          local.get 6
          i64.const 24
          i64.and
          i64.eqz
          br_if 1 (;@2;)
        end
        local.get 4
        local.get 7
        i32.wrap_i64
        local.tee 3
        i32.add
        local.set 0
        local.get 7
        local.get 6
        i64.const 248
        i64.and
        local.tee 8
        i64.sub
        local.set 7
        local.get 2
        i32.const 16
        i32.add
        local.get 3
        i32.add
        local.set 3
        loop  ;; label = @3
          local.get 3
          local.get 0
          i64.load align=1
          i64.store
          local.get 0
          i32.const 8
          i32.add
          local.set 0
          local.get 3
          i32.const 8
          i32.add
          local.set 3
          local.get 7
          i64.const 8
          i64.add
          local.tee 7
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
        end
        local.get 8
        local.set 7
        local.get 8
        local.get 6
        i64.eq
        br_if 1 (;@1;)
      end
      local.get 7
      i64.const -1
      i64.xor
      local.get 6
      i64.add
      local.set 11
      block  ;; label = @2
        local.get 6
        i64.const 3
        i64.and
        local.tee 8
        i64.eqz
        br_if 0 (;@2;)
        local.get 4
        local.get 7
        i32.wrap_i64
        local.tee 3
        i32.add
        local.set 0
        local.get 2
        i32.const 16
        i32.add
        local.get 3
        i32.add
        local.set 3
        loop  ;; label = @3
          local.get 3
          local.get 0
          i32.load8_u
          i32.store8
          local.get 0
          i32.const 1
          i32.add
          local.set 0
          local.get 3
          i32.const 1
          i32.add
          local.set 3
          local.get 7
          i64.const 1
          i64.add
          local.set 7
          local.get 8
          i64.const -1
          i64.add
          local.tee 8
          i64.const 0
          i64.ne
          br_if 0 (;@3;)
        end
      end
      local.get 11
      i64.const 3
      i64.lt_u
      br_if 0 (;@1;)
      local.get 6
      local.get 7
      i64.sub
      local.set 8
      local.get 7
      i32.wrap_i64
      local.set 13
      local.get 2
      i32.const 16
      i32.add
      local.set 12
      loop  ;; label = @2
        local.get 12
        local.get 13
        i32.add
        local.tee 0
        local.get 4
        local.get 13
        i32.add
        local.tee 3
        i32.load8_u
        i32.store8
        local.get 0
        i32.const 1
        i32.add
        local.get 3
        i32.const 1
        i32.add
        i32.load8_u
        i32.store8
        local.get 0
        i32.const 2
        i32.add
        local.get 3
        i32.const 2
        i32.add
        i32.load8_u
        i32.store8
        local.get 0
        i32.const 3
        i32.add
        local.get 3
        i32.const 3
        i32.add
        i32.load8_u
        i32.store8
        local.get 4
        i32.const 4
        i32.add
        local.set 4
        local.get 12
        i32.const 4
        i32.add
        local.set 12
        local.get 8
        i64.const -4
        i64.add
        local.tee 8
        i64.eqz
        i32.eqz
        br_if 0 (;@2;)
      end
    end
    local.get 2
    i32.const 16
    i32.add
    local.get 6
    i32.wrap_i64
    i32.add
    i32.const 10
    i32.store8
    local.get 5
    local.get 2
    i32.const 16
    i32.add
    i32.add
    i32.const 1
    i32.add
    i32.const 2570
    i32.store16 align=1
    local.get 2
    i32.const 12
    i32.add
    local.get 2
    i32.const 16
    i32.add
    local.get 5
    local.get 1
    call $ocall_write_sealed_data
    drop
    block  ;; label = @1
      i32.const 0
      i32.load
      local.get 2
      i32.load offset=24028
      i32.ne
      br_if 0 (;@1;)
      local.get 2
      i32.const 24032
      i32.add
      global.set $__stack_pointer
      return
    end
    call $__stack_chk_fail
    unreachable)
  (func $ocall_print_string (type 10) (param i32) (result i32)
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
  (func $ocall_read_config_data (type 10) (param i32) (result i32)
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
        i32.const 1
        local.get 3
        call $sgx_ocall
        local.set 2
      end
      call $sgx_ocfree
    end
    local.get 2)
  (func $ocall_read_log_messages (type 10) (param i32) (result i32)
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
        i32.const 2
        local.get 3
        call $sgx_ocall
        local.set 2
      end
      call $sgx_ocfree
    end
    local.get 2)
  (func $ocall_listen_log_messages (type 15) (result i32)
    i32.const 3
    i32.const 0
    call $sgx_ocall)
  (func $ocall_write_region_data (type 7) (param i32 i32 i32) (result i32)
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
      i32.const 4
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
  (func $ocall_read_region_data (type 13) (param i32 i32 i32 i32) (result i32)
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
        i32.const 5
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
  (func $ocall_write_sealed_data (type 13) (param i32 i32 i32 i32) (result i32)
    (local i64 i64 i32 i64 i32 i64 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 3
        br_if 0 (;@2;)
        i64.const 0
        local.set 4
        br 1 (;@1;)
      end
      local.get 3
      call $strlen
      i64.const 1
      i64.add
      local.set 4
    end
    local.get 2
    i64.extend_i32_u
    local.set 5
    block  ;; label = @1
      local.get 1
      i32.eqz
      br_if 0 (;@1;)
      local.get 1
      local.get 5
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    block  ;; label = @1
      local.get 3
      i32.eqz
      br_if 0 (;@1;)
      local.get 3
      local.get 4
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 2
    local.set 6
    block  ;; label = @1
      local.get 4
      local.get 5
      i64.const 32
      i64.add
      i64.const 32
      local.get 1
      select
      i64.add
      local.tee 7
      local.get 4
      i64.lt_u
      br_if 0 (;@1;)
      i32.const 1
      local.set 6
      block  ;; label = @2
        local.get 7
        call $sgx_ocalloc
        local.tee 8
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        i64.const -32
        i64.add
        local.set 7
        local.get 8
        i64.extend_i32_u
        i64.const 32
        i64.add
        local.tee 9
        i32.wrap_i64
        local.set 10
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 8
            local.get 10
            i32.store offset=8
            local.get 10
            local.get 7
            local.get 1
            local.get 5
            call $memcpy_s
            br_if 2 (;@2;)
            local.get 7
            local.get 5
            i64.sub
            local.set 7
            local.get 9
            local.get 5
            i64.add
            i32.wrap_i64
            local.set 10
            br 1 (;@3;)
          end
          local.get 8
          i32.const 0
          i32.store offset=8
        end
        local.get 8
        local.get 2
        i32.store offset=16
        block  ;; label = @3
          block  ;; label = @4
            local.get 3
            i32.eqz
            br_if 0 (;@4;)
            local.get 8
            local.get 10
            i32.store offset=24
            local.get 10
            local.get 7
            local.get 3
            local.get 4
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 8
          i32.const 0
          i32.store offset=24
        end
        i32.const 6
        local.get 8
        call $sgx_ocall
        local.tee 6
        br_if 0 (;@2;)
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 8
        i32.load
        i32.store
      end
      call $sgx_ocfree
    end
    local.get 6)
  (func $ocall_read_sealed_data (type 5) (param i32 i32) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          br_if 0 (;@3;)
          i64.const 0
          local.set 2
          br 1 (;@2;)
        end
        i32.const 2
        local.set 3
        local.get 1
        local.get 1
        call $strlen
        i64.const 1
        i64.add
        local.tee 2
        call $sgx_is_within_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 2
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
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 4
            local.get 4
            i32.const 16
            i32.add
            local.tee 5
            i32.store offset=8
            local.get 5
            local.get 2
            local.get 1
            local.get 2
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 4
          i32.const 0
          i32.store offset=8
        end
        i32.const 7
        local.get 4
        call $sgx_ocall
        local.tee 3
        br_if 0 (;@2;)
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 4
        i32.load
        i32.store
      end
      call $sgx_ocfree
    end
    local.get 3)
  (func $ocall_pointer_user_check (type 10) (param i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 8
      call $sgx_ocalloc
      local.tee 1
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 1
    local.get 0
    i32.store
    i32.const 8
    local.get 1
    call $sgx_ocall
    local.set 1
    call $sgx_ocfree
    local.get 1)
  (func $ocall_pointer_in (type 10) (param i32) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i64.const 0
        local.set 1
        br 1 (;@1;)
      end
      i64.const 4
      local.set 1
      local.get 0
      i64.const 4
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 1
    local.set 2
    block  ;; label = @1
      local.get 1
      i64.const 8
      i64.or
      call $sgx_ocalloc
      local.tee 3
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          local.get 3
          i64.extend_i32_u
          i64.const 8
          i64.add
          i32.wrap_i64
          local.tee 4
          i32.store
          local.get 4
          local.get 1
          local.get 0
          i64.const 4
          call $memcpy_s
          i32.eqz
          br_if 1 (;@2;)
          br 2 (;@1;)
        end
        local.get 3
        i32.const 0
        i32.store
      end
      i32.const 9
      local.get 3
      call $sgx_ocall
      local.set 2
    end
    call $sgx_ocfree
    local.get 2)
  (func $ocall_pointer_out (type 10) (param i32) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i64.const 8
        local.set 1
        br 1 (;@1;)
      end
      i64.const 12
      local.set 1
      local.get 0
      i64.const 4
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 1
    local.set 2
    block  ;; label = @1
      local.get 1
      call $sgx_ocalloc
      local.tee 3
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          br_if 0 (;@3;)
          local.get 3
          i32.const 0
          i32.store
          i32.const 10
          local.get 3
          call $sgx_ocall
          local.set 3
          br 1 (;@2;)
        end
        local.get 3
        local.get 3
        i64.extend_i32_u
        i64.const 8
        i64.add
        i32.wrap_i64
        local.tee 4
        i32.store
        local.get 4
        i32.const 0
        i32.store align=1
        i32.const 10
        local.get 3
        call $sgx_ocall
        local.tee 3
        br_if 0 (;@2;)
        i32.const 0
        local.set 3
        local.get 0
        i64.const 4
        local.get 4
        i64.const 4
        call $memcpy_s
        br_if 1 (;@1;)
      end
      local.get 3
      local.set 2
    end
    call $sgx_ocfree
    local.get 2)
  (func $ocall_pointer_in_out (type 10) (param i32) (result i32)
    (local i64 i32 i32 i64 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i64.const 0
        local.set 1
        br 1 (;@1;)
      end
      i64.const 4
      local.set 1
      local.get 0
      i64.const 4
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 1
    local.set 2
    block  ;; label = @1
      block  ;; label = @2
        local.get 1
        i64.const 8
        i64.or
        call $sgx_ocalloc
        local.tee 3
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        local.get 3
        i64.extend_i32_u
        i64.const 8
        i64.add
        local.tee 4
        i64.store32
        local.get 4
        i32.wrap_i64
        local.tee 5
        local.get 1
        local.get 0
        i64.const 4
        call $memcpy_s
        br_if 0 (;@2;)
        i32.const 11
        local.get 3
        call $sgx_ocall
        local.tee 2
        br_if 0 (;@2;)
        i32.const 1
        local.set 2
        local.get 0
        i64.const 4
        local.get 5
        i64.const 4
        call $memcpy_s
        br_if 0 (;@2;)
        i32.const 0
        local.set 2
      end
      call $sgx_ocfree
      local.get 2
      return
    end
    local.get 3
    i32.const 0
    i32.store
    i32.const 11
    local.get 3
    call $sgx_ocall
    local.set 0
    call $sgx_ocfree
    local.get 0)
  (func $memccpy (type 23) (param i32 i32 i32 i32 i64) (result i32)
    (local i32 i64 i64 i64 i32 i32 i32)
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
      local.get 2
      i32.eqz
      br_if 0 (;@1;)
      local.get 2
      local.get 4
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 2
    local.set 5
    block  ;; label = @1
      local.get 4
      i64.const 0
      local.get 1
      select
      local.tee 6
      i64.const -41
      i64.gt_u
      br_if 0 (;@1;)
      local.get 4
      i64.const 0
      local.get 2
      select
      local.tee 7
      local.get 6
      i64.add
      local.tee 8
      i64.const 40
      i64.add
      local.tee 6
      local.get 7
      i64.lt_u
      br_if 0 (;@1;)
      i32.const 1
      local.set 5
      block  ;; label = @2
        local.get 6
        call $sgx_ocalloc
        local.tee 9
        i32.eqz
        br_if 0 (;@2;)
        local.get 9
        i64.extend_i32_u
        i64.const 40
        i64.add
        local.tee 6
        i32.wrap_i64
        local.set 10
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 9
            local.get 10
            i32.store offset=8
            local.get 10
            local.get 8
            local.get 1
            local.get 4
            call $memcpy_s
            br_if 2 (;@2;)
            local.get 8
            local.get 4
            i64.sub
            local.set 8
            local.get 6
            local.get 4
            i64.add
            i32.wrap_i64
            local.set 11
            br 1 (;@3;)
          end
          local.get 9
          i32.const 0
          i32.store offset=8
          local.get 10
          local.set 11
          i32.const 0
          local.set 10
        end
        block  ;; label = @3
          block  ;; label = @4
            local.get 2
            i32.eqz
            br_if 0 (;@4;)
            local.get 9
            local.get 11
            i32.store offset=16
            local.get 11
            local.get 8
            local.get 2
            local.get 4
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 9
          i32.const 0
          i32.store offset=16
        end
        local.get 9
        local.get 4
        i64.store offset=32
        local.get 9
        local.get 3
        i32.store offset=24
        block  ;; label = @3
          i32.const 12
          local.get 9
          call $sgx_ocall
          local.tee 2
          br_if 0 (;@3;)
          block  ;; label = @4
            local.get 0
            i32.eqz
            br_if 0 (;@4;)
            local.get 0
            local.get 9
            i32.load
            i32.store
          end
          local.get 1
          i32.eqz
          br_if 0 (;@3;)
          local.get 1
          local.get 4
          local.get 10
          local.get 4
          call $memcpy_s
          br_if 1 (;@2;)
        end
        local.get 2
        local.set 5
      end
      call $sgx_ocfree
    end
    local.get 5)
  (func $ocall_function_allow (type 15) (result i32)
    i32.const 13
    i32.const 0
    call $sgx_ocall)
  (func $sgx_oc_cpuidex (type 7) (param i32 i32 i32) (result i32)
    (local i64 i32 i32 i32)
    block  ;; label = @1
      block  ;; label = @2
        local.get 0
        br_if 0 (;@2;)
        i64.const 16
        local.set 3
        br 1 (;@1;)
      end
      i64.const 32
      local.set 3
      local.get 0
      i64.const 16
      call $sgx_is_within_enclave
      br_if 0 (;@1;)
      i32.const 2
      return
    end
    i32.const 1
    local.set 4
    block  ;; label = @1
      local.get 3
      call $sgx_ocalloc
      local.tee 5
      i32.eqz
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 0
          i32.eqz
          br_if 0 (;@3;)
          local.get 5
          local.get 5
          i64.extend_i32_u
          i64.const 16
          i64.add
          local.tee 3
          i64.store32
          local.get 3
          i32.wrap_i64
          local.tee 6
          i32.const 8
          i32.add
          i64.const 0
          i64.store align=1
          local.get 6
          i64.const 0
          i64.store align=1
          br 1 (;@2;)
        end
        i32.const 0
        local.set 6
        local.get 5
        i32.const 0
        i32.store
      end
      local.get 5
      local.get 2
      i32.store offset=12
      local.get 5
      local.get 1
      i32.store offset=8
      block  ;; label = @2
        i32.const 14
        local.get 5
        call $sgx_ocall
        local.tee 5
        br_if 0 (;@2;)
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        i64.const 16
        local.get 6
        i64.const 16
        call $memcpy_s
        br_if 1 (;@1;)
      end
      local.get 5
      local.set 4
    end
    call $sgx_ocfree
    local.get 4)
  (func $sgx_thread_wait_untrusted_event_ocall (type 5) (param i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 16
      call $sgx_ocalloc
      local.tee 2
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 2
    local.get 1
    i32.store offset=8
    block  ;; label = @1
      i32.const 15
      local.get 2
      call $sgx_ocall
      local.tee 1
      br_if 0 (;@1;)
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 2
      i32.load
      i32.store
    end
    call $sgx_ocfree
    local.get 1)
  (func $sgx_thread_set_untrusted_event_ocall (type 5) (param i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 16
      call $sgx_ocalloc
      local.tee 2
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 2
    local.get 1
    i32.store offset=8
    block  ;; label = @1
      i32.const 16
      local.get 2
      call $sgx_ocall
      local.tee 1
      br_if 0 (;@1;)
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 2
      i32.load
      i32.store
    end
    call $sgx_ocfree
    local.get 1)
  (func $sgx_thread_setwait_untrusted_events_ocall (type 7) (param i32 i32 i32) (result i32)
    (local i32)
    block  ;; label = @1
      i64.const 24
      call $sgx_ocalloc
      local.tee 3
      br_if 0 (;@1;)
      call $sgx_ocfree
      i32.const 1
      return
    end
    local.get 3
    local.get 2
    i32.store offset=16
    local.get 3
    local.get 1
    i32.store offset=8
    block  ;; label = @1
      i32.const 17
      local.get 3
      call $sgx_ocall
      local.tee 1
      br_if 0 (;@1;)
      local.get 0
      i32.eqz
      br_if 0 (;@1;)
      local.get 0
      local.get 3
      i32.load
      i32.store
    end
    call $sgx_ocfree
    local.get 1)
  (func $sgx_thread_set_multiple_untrusted_events_ocall (type 12) (param i32 i32 i64) (result i32)
    (local i64 i64 i32 i32 i32)
    local.get 2
    i64.const 3
    i64.shl
    local.set 3
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          br_if 0 (;@3;)
          i64.const 0
          local.set 4
          br 1 (;@2;)
        end
        i32.const 2
        local.set 5
        local.get 1
        local.get 3
        call $sgx_is_within_enclave
        i32.eqz
        br_if 1 (;@1;)
        local.get 3
        local.set 4
        local.get 3
        i64.const -25
        i64.gt_u
        br_if 1 (;@1;)
      end
      i32.const 1
      local.set 5
      block  ;; label = @2
        local.get 4
        i64.const 24
        i64.add
        call $sgx_ocalloc
        local.tee 6
        i32.eqz
        br_if 0 (;@2;)
        block  ;; label = @3
          block  ;; label = @4
            local.get 1
            i32.eqz
            br_if 0 (;@4;)
            local.get 6
            local.get 6
            i64.extend_i32_u
            i64.const 24
            i64.add
            i32.wrap_i64
            local.tee 7
            i32.store offset=8
            local.get 7
            local.get 4
            local.get 1
            local.get 3
            call $memcpy_s
            i32.eqz
            br_if 1 (;@3;)
            br 2 (;@2;)
          end
          local.get 6
          i32.const 0
          i32.store offset=8
        end
        local.get 6
        local.get 2
        i64.store offset=16
        i32.const 18
        local.get 6
        call $sgx_ocall
        local.tee 5
        br_if 0 (;@2;)
        local.get 0
        i32.eqz
        br_if 0 (;@2;)
        local.get 0
        local.get 6
        i32.load
        i32.store
      end
      call $sgx_ocfree
    end
    local.get 5)
  (func $printf (type 16) (param i32 i32)
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
  (func $create_block__ (type 6)
    (local i32 i32)
    i32.const 3214
    i32.const 0
    call $printf
    block  ;; label = @1
      block  ;; label = @2
        i32.const 0
        i32.load offset=3760
        br_if 0 (;@2;)
        i32.const 100
        local.set 0
        i32.const 0
        i32.const 100
        i32.store offset=3764
        i32.const 0
        i32.const 0
        i32.load offset=3768
        local.tee 1
        i32.store offset=3760
        br 1 (;@1;)
      end
      i32.const 0
      i32.const 0
      i32.load offset=3776
      local.tee 1
      i32.store offset=3760
      i32.const 0
      i32.const 0
      i32.load offset=3764
      i32.const 1
      i32.add
      local.tee 0
      i32.store offset=3764
    end
    i32.const 0
    local.get 0
    i32.store offset=3772
    i32.const 0
    local.get 1
    local.get 1
    call $strlen
    i32.wrap_i64
    local.get 0
    call $get_next_block_key
    i32.store offset=3776
    block  ;; label = @1
      i32.const 0
      i32.load offset=3772
      i32.const 0
      i32.load offset=3764
      i32.eq
      br_if 0 (;@1;)
      i32.const 3261
      i32.const 0
      call $printf
      return
    end
    i32.const 0
    i32.const 0
    i32.store offset=3780)
  (func $init_config_config_data*_ (type 4) (param i32)
    (local i32)
    i32.const 3181
    i32.const 0
    call $printf
    local.get 0
    i64.const 64
    call $malloc
    i32.store
    local.get 0
    i64.const 64
    call $malloc
    i32.store offset=4
    local.get 0
    i64.const 64
    call $malloc
    i32.store offset=8
    i64.const 4096
    call $malloc
    local.set 1
    local.get 0
    i64.const 0
    i64.store offset=16
    local.get 0
    local.get 1
    i32.store offset=12)
  (func $abs_double_ (type 24) (param f64) (result f64)
    local.get 0
    local.get 0
    f64.neg
    local.get 0
    f64.const 0x0p+0 (;=0;)
    f64.ge
    select)
  (func $almost_equal_double__double_ (type 25) (param f64 f64) (result i32)
    (local f64)
    local.get 0
    local.get 1
    f64.sub
    local.tee 2
    local.get 2
    f64.neg
    local.get 2
    f64.const 0x0p+0 (;=0;)
    f64.ge
    select
    local.get 0
    local.get 1
    f64.add
    local.tee 0
    local.get 0
    f64.neg
    local.get 0
    f64.const 0x0p+0 (;=0;)
    f64.ge
    select
    f64.const 0x1.b7cdfd9d7bdbbp-34 (;=1e-10;)
    f64.mul
    local.tee 0
    local.get 0
    f64.add
    f64.le)
  (func $almost_equal_float__float_ (type 26) (param f32 f32) (result i32)
    (local f32 f64)
    local.get 0
    local.get 1
    f32.sub
    local.tee 2
    f64.promote_f32
    local.tee 3
    local.get 3
    f64.neg
    local.get 2
    f32.const 0x0p+0 (;=0;)
    f32.ge
    select
    local.get 0
    local.get 1
    f32.add
    local.tee 0
    f64.promote_f32
    local.tee 3
    local.get 3
    f64.neg
    local.get 0
    f32.const 0x0p+0 (;=0;)
    f32.ge
    select
    f64.const 0x1.b7cdfd9d7bdbbp-34 (;=1e-10;)
    f64.mul
    local.tee 3
    local.get 3
    f64.add
    f64.le)
  (func $checksum_internal_char*__unsigned_long_ (type 0) (param i32 i64) (result i32)
    (local i32 i64 i64 i64 i32 i64 i64 i32 i32 i32 i32 i32 i32 i32 i32)
    i32.const 0
    local.set 2
    block  ;; label = @1
      local.get 1
      i64.const 2
      i64.lt_u
      br_if 0 (;@1;)
      block  ;; label = @2
        block  ;; label = @3
          local.get 1
          i64.const -2
          i64.add
          local.tee 3
          i64.const 14
          i64.ge_u
          br_if 0 (;@3;)
          i32.const 0
          local.set 2
          br 1 (;@2;)
        end
        local.get 3
        i64.const 1
        i64.shr_u
        i64.const 1
        i64.add
        local.tee 4
        i64.const -8
        i64.and
        local.tee 5
        i32.wrap_i64
        local.set 6
        local.get 5
        i64.const -8
        i64.add
        local.tee 3
        i64.const 3
        i64.shr_u
        i64.const 1
        i64.add
        local.tee 7
        i64.const 1
        i64.and
        local.set 8
        block  ;; label = @3
          block  ;; label = @4
            local.get 3
            i64.eqz
            i32.eqz
            br_if 0 (;@4;)
            i32.const 0
            local.set 2
            i64.const 0
            local.set 3
            i32.const 0
            local.set 9
            i32.const 0
            local.set 10
            i32.const 0
            local.set 11
            i32.const 0
            local.set 12
            i32.const 0
            local.set 13
            i32.const 0
            local.set 14
            i32.const 0
            local.set 15
            br 1 (;@3;)
          end
          i64.const 0
          local.get 7
          i64.const 4611686018427387902
          i64.and
          i64.sub
          local.set 7
          i32.const 0
          local.set 2
          local.get 0
          local.set 16
          i64.const 0
          local.set 3
          i32.const 0
          local.set 9
          i32.const 0
          local.set 10
          i32.const 0
          local.set 11
          i32.const 0
          local.set 12
          i32.const 0
          local.set 13
          i32.const 0
          local.set 14
          i32.const 0
          local.set 15
          loop  ;; label = @4
            local.get 9
            local.get 16
            i32.load16_s offset=2
            i32.add
            local.get 16
            i32.const 18
            i32.add
            i32.load16_s
            i32.add
            local.set 9
            local.get 2
            local.get 16
            i32.load16_s
            i32.add
            local.get 16
            i32.const 16
            i32.add
            i32.load16_s
            i32.add
            local.set 2
            local.get 14
            local.get 16
            i32.const 12
            i32.add
            i32.load16_s
            i32.add
            local.get 16
            i32.const 28
            i32.add
            i32.load16_s
            i32.add
            local.set 14
            local.get 13
            local.get 16
            i32.const 10
            i32.add
            i32.load16_s
            i32.add
            local.get 16
            i32.const 26
            i32.add
            i32.load16_s
            i32.add
            local.set 13
            local.get 12
            local.get 16
            i32.const 8
            i32.add
            i32.load16_s
            i32.add
            local.get 16
            i32.const 24
            i32.add
            i32.load16_s
            i32.add
            local.set 12
            local.get 10
            local.get 16
            i32.load16_s offset=4
            i32.add
            local.get 16
            i32.const 20
            i32.add
            i32.load16_s
            i32.add
            local.set 10
            local.get 15
            local.get 16
            i32.const 14
            i32.add
            i32.load16_s
            i32.add
            local.get 16
            i32.const 30
            i32.add
            i32.load16_s
            i32.add
            local.set 15
            local.get 11
            local.get 16
            i32.const 6
            i32.add
            i32.load16_s
            i32.add
            local.get 16
            i32.const 22
            i32.add
            i32.load16_s
            i32.add
            local.set 11
            local.get 16
            i32.const 32
            i32.add
            local.set 16
            local.get 3
            i64.const 16
            i64.add
            local.set 3
            local.get 7
            i64.const 2
            i64.add
            local.tee 7
            i64.const 0
            i64.ne
            br_if 0 (;@4;)
          end
        end
        local.get 5
        i64.const 1
        i64.shl
        local.set 7
        local.get 6
        i32.const 1
        i32.shl
        local.set 6
        block  ;; label = @3
          local.get 8
          i64.eqz
          br_if 0 (;@3;)
          local.get 10
          local.get 0
          local.get 3
          i32.wrap_i64
          i32.const 1
          i32.shl
          i32.add
          local.tee 16
          i32.load16_s offset=4
          i32.add
          local.set 10
          local.get 9
          local.get 16
          i32.load16_s offset=2
          i32.add
          local.set 9
          local.get 2
          local.get 16
          i32.load16_s
          i32.add
          local.set 2
          local.get 11
          local.get 16
          i32.const 6
          i32.add
          i32.load16_s
          i32.add
          local.set 11
          local.get 15
          local.get 16
          i32.const 14
          i32.add
          i32.load16_s
          i32.add
          local.set 15
          local.get 14
          local.get 16
          i32.const 12
          i32.add
          i32.load16_s
          i32.add
          local.set 14
          local.get 13
          local.get 16
          i32.const 10
          i32.add
          i32.load16_s
          i32.add
          local.set 13
          local.get 12
          local.get 16
          i32.const 8
          i32.add
          i32.load16_s
          i32.add
          local.set 12
        end
        local.get 1
        local.get 7
        i64.sub
        local.set 1
        local.get 0
        local.get 6
        i32.add
        local.set 0
        local.get 12
        local.get 2
        i32.add
        local.get 14
        local.get 10
        i32.add
        i32.add
        local.get 13
        local.get 9
        i32.add
        local.get 15
        local.get 11
        i32.add
        i32.add
        i32.add
        local.set 2
        local.get 4
        local.get 5
        i64.eq
        br_if 1 (;@1;)
      end
      local.get 0
      local.set 16
      loop  ;; label = @2
        local.get 2
        local.get 16
        i32.load16_s
        i32.add
        local.set 2
        local.get 16
        i32.const 2
        i32.add
        local.tee 0
        local.set 16
        local.get 1
        i64.const -2
        i64.add
        local.tee 1
        i64.const 1
        i64.gt_u
        br_if 0 (;@2;)
      end
    end
    block  ;; label = @1
      local.get 1
      i64.const 1
      i64.ne
      br_if 0 (;@1;)
      local.get 2
      local.get 0
      i32.load8_s
      i32.add
      local.set 2
    end
    local.get 2
    i32.const -1
    i32.xor)
  (func $get_buffer_len_char_const*_ (type 3) (param i32) (result i64)
    i64.const 40)
  (table (;0;) 51 51 funcref)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 69600))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1432))
  (global (;3;) i32 (i32.const 1024))
  (global (;4;) i32 (i32.const 4056))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 69600))
  (global (;7;) i32 (i32.const 0))
  (global (;8;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "process_log" (func $process_log))
  (export "verify_block_messages" (func $verify_block_messages))
  (export "generate_config" (func $generate_config))
  (export "startup_phase" (func $startup_phase))
  (export "reset_block_key" (func $reset_block_key))
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
  (export "ecall_pointer_sizefunc" (func $ecall_pointer_sizefunc))
  (export "ocall_pointer_attr" (func $ocall_pointer_attr))
  (export "ecall_array_user_check" (func $ecall_array_user_check))
  (export "ecall_array_in" (func $ecall_array_in))
  (export "ecall_array_out" (func $ecall_array_out))
  (export "ecall_array_in_out" (func $ecall_array_in_out))
  (export "ecall_array_isary" (func $ecall_array_isary))
  (export "ecall_function_calling_convs" (func $ecall_function_calling_convs))
  (export "ecall_function_public" (func $ecall_function_public))
  (export "ecall_function_private" (func $ecall_function_private))
  (export "ecall_malloc_free" (func $ecall_malloc_free))
  (export "ecall_sgx_cpuid" (func $ecall_sgx_cpuid))
  (export "ecall_exception" (func $ecall_exception))
  (export "ecall_map" (func $ecall_map))
  (export "ecall_increase_counter" (func $ecall_increase_counter))
  (export "ecall_producer" (func $ecall_producer))
  (export "ecall_consumer" (func $ecall_consumer))
  (export "get_next_block_key" (func $get_next_block_key))
  (export "get_next_message_key" (func $get_next_message_key))
  (export "get_mac" (func $get_mac))
  (export "hash" (func $hash))
  (export "compareHashValues" (func $compareHashValues))
  (export "reverse" (func $reverse))
  (export "itoa" (func $itoa))
  (export "myAtoi" (func $myAtoi))
  (export "get_hash" (func $get_hash))
  (export "seal_data" (func $seal_data))
  (export "seal_and_write" (func $seal_and_write))
  (export "ocall_print_string" (func $ocall_print_string))
  (export "ocall_read_config_data" (func $ocall_read_config_data))
  (export "ocall_read_log_messages" (func $ocall_read_log_messages))
  (export "ocall_listen_log_messages" (func $ocall_listen_log_messages))
  (export "ocall_write_region_data" (func $ocall_write_region_data))
  (export "ocall_read_region_data" (func $ocall_read_region_data))
  (export "ocall_write_sealed_data" (func $ocall_write_sealed_data))
  (export "ocall_read_sealed_data" (func $ocall_read_sealed_data))
  (export "ocall_pointer_user_check" (func $ocall_pointer_user_check))
  (export "ocall_pointer_in" (func $ocall_pointer_in))
  (export "ocall_pointer_out" (func $ocall_pointer_out))
  (export "ocall_pointer_in_out" (func $ocall_pointer_in_out))
  (export "memccpy" (func $memccpy))
  (export "ocall_function_allow" (func $ocall_function_allow))
  (export "sgx_oc_cpuidex" (func $sgx_oc_cpuidex))
  (export "sgx_thread_wait_untrusted_event_ocall" (func $sgx_thread_wait_untrusted_event_ocall))
  (export "sgx_thread_set_untrusted_event_ocall" (func $sgx_thread_set_untrusted_event_ocall))
  (export "sgx_thread_setwait_untrusted_events_ocall" (func $sgx_thread_setwait_untrusted_events_ocall))
  (export "sgx_thread_set_multiple_untrusted_events_ocall" (func $sgx_thread_set_multiple_untrusted_events_ocall))
  (export "printf" (func $printf))
  (export "_Z12create_blockv" (func $create_block__))
  (export "_Z11init_configP11config_data" (func $init_config_config_data*_))
  (export "_Z3absd" (func $abs_double_))
  (export "_Z12almost_equaldd" (func $almost_equal_double__double_))
  (export "_Z12almost_equalff" (func $almost_equal_float__float_))
  (export "_Z17checksum_internalPcm" (func $checksum_internal_char*__unsigned_long_))
  (export "_Z14get_buffer_lenPKc" (func $get_buffer_len_char_const*_))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "__indirect_function_table" (table 0))
  (export "__dso_handle" (global 3))
  (export "__data_end" (global 4))
  (export "__global_base" (global 5))
  (export "__heap_base" (global 6))
  (export "__memory_base" (global 7))
  (export "__table_base" (global 8))
  (elem (;0;) (i32.const 1) func $sgx_process_log $sgx_verify_block_messages $sgx_generate_config $sgx_startup_phase $sgx_reset_block_key $sgx_ecall_type_char $sgx_ecall_type_int $sgx_ecall_type_float $sgx_ecall_type_double $sgx_ecall_type_size_t $sgx_ecall_type_wchar_t $sgx_ecall_type_struct $sgx_ecall_type_enum_union $sgx_ecall_pointer_user_check $sgx_ecall_pointer_in $sgx_ecall_pointer_out $sgx_ecall_pointer_in_out $sgx_ecall_pointer_string $sgx_ecall_pointer_string_const $sgx_ecall_pointer_size $sgx_ecall_pointer_count $sgx_ecall_pointer_isptr_readonly $sgx_ecall_pointer_sizefunc $sgx_ocall_pointer_attr $sgx_ecall_array_user_check $sgx_ecall_array_in $sgx_ecall_array_out $sgx_ecall_array_in_out $sgx_ecall_array_isary $sgx_ecall_function_calling_convs $sgx_ecall_function_public $sgx_ecall_function_private $sgx_ecall_malloc_free $sgx_ecall_sgx_cpuid $sgx_ecall_exception $sgx_ecall_map $sgx_ecall_increase_counter $sgx_ecall_producer $sgx_ecall_consumer $sgx_get_next_block_key $sgx_get_next_message_key $sgx_get_mac $sgx_hash $sgx_compareHashValues $sgx_reverse $sgx_itoa $sgx_myAtoi $sgx_get_hash $sgx_seal_data.124 $sgx_seal_and_write)
  (data $.rodata (i32.const 1024) "2\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00\03\00\00\00\00\00\00\00\04\00\00\00\00\00\00\00\05\00\00\00\00\00\00\00\06\00\00\00\00\00\00\00\07\00\00\00\00\00\00\00\08\00\00\00\00\00\00\00\09\00\00\00\00\00\00\00\0a\00\00\00\00\00\00\00\0b\00\00\00\00\00\00\00\0c\00\00\00\00\00\00\00\0d\00\00\00\00\00\00\00\0e\00\00\00\00\00\00\00\0f\00\00\00\00\00\00\00\10\00\00\00\00\00\00\00\11\00\00\00\00\00\00\00\12\00\00\00\00\00\00\00\13\00\00\00\00\00\00\00\14\00\00\00\00\00\00\00\15\00\00\00\00\00\00\00\16\00\00\00\00\00\00\00\17\00\00\00\00\00\00\00\18\00\00\00\00\00\00\00\19\00\00\00\00\00\00\00\1a\00\00\00\00\00\00\00\1b\00\00\00\00\00\00\00\1c\00\00\00\00\00\00\00\1d\00\00\00\00\00\00\00\1e\00\00\00\00\00\00\00\1f\00\00\00\00\00\00\00 \00\00\00\01\00\00\00!\00\00\00\00\00\00\00\22\00\00\00\00\00\00\00#\00\00\00\00\00\00\00$\00\00\00\00\00\00\00%\00\00\00\00\00\00\00&\00\00\00\00\00\00\00'\00\00\00\00\00\00\00(\00\00\00\00\00\00\00)\00\00\00\00\00\00\00*\00\00\00\00\00\00\00+\00\00\00\00\00\00\00,\00\00\00\00\00\00\00-\00\00\00\00\00\00\00.\00\00\00\00\00\00\00/\00\00\00\00\00\00\000\00\00\00\00\00\00\001\00\00\00\00\00\00\002\00\00\00\00\00\00\00\13\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00ecall_array_isary\00\0aBlock verified successfully\00secret_root_key\00\0a%u %u\00ecall_array_out\00ecall_pointer_out\00ecall_array_in_out\00ecall_type_int\00ecall_type_struct\00ecall_type_float\00ecall_type_wchar_t\00ecall_type_size_t\00ecall_function_calling_convs\00ocall_pointer_attr\00ecall_type_char\00Enclave/Edger8rSyntax/Arrays.cpp\00Enclave/Edger8rSyntax/Pointers.cpp\00Enclave/Edger8rSyntax/Functions.cpp\00Enclave/Edger8rSyntax/Types.cpp\00ecall_type_enum_union\00ecall_array_in\00\0aDetected intrusion in current block\00ecall_array_user_check\00arr[i] == i\00ecall_type_double\00ecall_pointer_sizefunc\00SGX_SUCCESS\00val == (size_t)12345678\00val.struct_foo_1 == 5678\00val == (wchar_t)0x1234\00val == 1234\00val.struct_foo_0 == 1234\00val == 0x12\000987654321\00val1 == ENUM_FOO_0\00*val == 0\00arr[i] == 0\00tmp[i] == 0\00memcmp(s1, s2, strlen(s1)) == 0\00\0aInitializing log configuration.\00\0aCreating a new block.\00\0aRunning startup_phase.\00\0aRoll-back attack detected..\00Filename-%s-\00almost_equal(val, (double)1234.5678)\00almost_equal(val, (float)1234.0)\00Checksum(0x%p, %zu) = 0x%x\0a\00")
  (data $.data (i32.const 3408) "\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00\00"))
