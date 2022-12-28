(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func))
  (type (;2;) (func (param i32) (result i32)))
  (type (;3;) (func (param i32 i32 i32) (result i32)))
  (type (;4;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32)))
  (type (;6;) (func (param i32 i32)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "__builtin_ia32_lfence" (func $__builtin_ia32_lfence (type 1)))
  (import "env" "malloc" (func $malloc (type 2)))
  (import "env" "memset" (func $memset (type 3)))
  (import "env" "memcpy_s" (func $memcpy_s (type 4)))
  (import "env" "free" (func $free (type 5)))
  (import "env" "strlen" (func $strlen (type 2)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 2)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 1)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 0)))
  (import "env" "vsnprintf" (func $vsnprintf (type 4)))
  (import "env" "strnlen" (func $strnlen (type 0)))
  (import "env" "memcpy" (func $memcpy (type 3)))
  (func $__wasm_call_ctors (type 1))
  (func $sgx_ecall_copy_information (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 32
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=24
    local.get 3
    i32.load offset=24
    local.set 4
    i32.const 0
    local.set 5
    local.get 4
    local.set 6
    local.get 5
    local.set 7
    local.get 6
    local.get 7
    i32.ne
    local.set 8
    i32.const 1
    local.set 9
    local.get 8
    local.get 9
    i32.and
    local.set 10
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 10
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=24
          local.set 11
          i32.const 8
          local.set 12
          local.get 11
          local.get 12
          call $sgx_is_outside_enclave
          local.set 13
          local.get 13
          br_if 1 (;@2;)
        end
        i32.const 2
        local.set 14
        local.get 3
        local.get 14
        i32.store offset=28
        br 1 (;@1;)
      end
      call $__builtin_ia32_lfence
      local.get 3
      i32.load offset=24
      local.set 15
      local.get 3
      local.get 15
      i32.store offset=20
      i32.const 0
      local.set 16
      local.get 3
      local.get 16
      i32.store offset=16
      local.get 3
      i32.load offset=20
      local.set 17
      local.get 17
      i32.load
      local.set 18
      local.get 3
      local.get 18
      i32.store offset=12
      local.get 3
      i32.load offset=20
      local.set 19
      local.get 19
      i32.load offset=4
      local.set 20
      local.get 3
      local.get 20
      i32.store offset=8
      local.get 3
      i32.load offset=8
      local.set 21
      i32.const 2
      local.set 22
      local.get 21
      local.get 22
      i32.shl
      local.set 23
      local.get 3
      local.get 23
      i32.store offset=4
      i32.const 0
      local.set 24
      local.get 3
      local.get 24
      i32.store
      local.get 3
      i32.load offset=8
      local.set 25
      i32.const 1073741823
      local.set 26
      local.get 25
      local.set 27
      local.get 26
      local.set 28
      local.get 27
      local.get 28
      i32.gt_u
      local.set 29
      i32.const 1
      local.set 30
      local.get 29
      local.get 30
      i32.and
      local.set 31
      block  ;; label = @2
        local.get 31
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2
        local.set 32
        local.get 3
        local.get 32
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=12
      local.set 33
      i32.const 0
      local.set 34
      local.get 33
      local.set 35
      local.get 34
      local.set 36
      local.get 35
      local.get 36
      i32.ne
      local.set 37
      i32.const 1
      local.set 38
      local.get 37
      local.get 38
      i32.and
      local.set 39
      block  ;; label = @2
        local.get 39
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=12
        local.set 40
        local.get 3
        i32.load offset=4
        local.set 41
        local.get 40
        local.get 41
        call $sgx_is_outside_enclave
        local.set 42
        local.get 42
        br_if 0 (;@2;)
        i32.const 2
        local.set 43
        local.get 3
        local.get 43
        i32.store offset=28
        br 1 (;@1;)
      end
      call $__builtin_ia32_lfence
      local.get 3
      i32.load offset=12
      local.set 44
      i32.const 0
      local.set 45
      local.get 44
      local.set 46
      local.get 45
      local.set 47
      local.get 46
      local.get 47
      i32.ne
      local.set 48
      i32.const 1
      local.set 49
      local.get 48
      local.get 49
      i32.and
      local.set 50
      block  ;; label = @2
        block  ;; label = @3
          local.get 50
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=4
          local.set 51
          local.get 51
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=4
          local.set 52
          i32.const 3
          local.set 53
          local.get 52
          local.get 53
          i32.and
          local.set 54
          block  ;; label = @4
            local.get 54
            i32.eqz
            br_if 0 (;@4;)
            i32.const 2
            local.set 55
            local.get 3
            local.get 55
            i32.store offset=16
            br 2 (;@2;)
          end
          local.get 3
          i32.load offset=4
          local.set 56
          local.get 56
          call $malloc
          local.set 57
          local.get 3
          local.get 57
          i32.store
          i32.const 0
          local.set 58
          local.get 57
          local.set 59
          local.get 58
          local.set 60
          local.get 59
          local.get 60
          i32.eq
          local.set 61
          i32.const 1
          local.set 62
          local.get 61
          local.get 62
          i32.and
          local.set 63
          block  ;; label = @4
            local.get 63
            i32.eqz
            br_if 0 (;@4;)
            i32.const 3
            local.set 64
            local.get 3
            local.get 64
            i32.store offset=16
            br 2 (;@2;)
          end
          local.get 3
          i32.load
          local.set 65
          local.get 3
          i32.load offset=4
          local.set 66
          i32.const 0
          local.set 67
          local.get 65
          local.get 67
          local.get 66
          call $memset
          drop
        end
        local.get 3
        i32.load
        local.set 68
        local.get 3
        i32.load offset=8
        local.set 69
        local.get 68
        local.get 69
        call $ecall_copy_information
        local.get 3
        i32.load
        local.set 70
        i32.const 0
        local.set 71
        local.get 70
        local.set 72
        local.get 71
        local.set 73
        local.get 72
        local.get 73
        i32.ne
        local.set 74
        i32.const 1
        local.set 75
        local.get 74
        local.get 75
        i32.and
        local.set 76
        block  ;; label = @3
          local.get 76
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=12
          local.set 77
          local.get 3
          i32.load offset=4
          local.set 78
          local.get 3
          i32.load
          local.set 79
          local.get 3
          i32.load offset=4
          local.set 80
          local.get 77
          local.get 78
          local.get 79
          local.get 80
          call $memcpy_s
          local.set 81
          block  ;; label = @4
            local.get 81
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 82
            local.get 3
            local.get 82
            i32.store offset=16
            br 2 (;@2;)
          end
        end
      end
      local.get 3
      i32.load
      local.set 83
      i32.const 0
      local.set 84
      local.get 83
      local.set 85
      local.get 84
      local.set 86
      local.get 85
      local.get 86
      i32.ne
      local.set 87
      i32.const 1
      local.set 88
      local.get 87
      local.get 88
      i32.and
      local.set 89
      block  ;; label = @2
        local.get 89
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load
        local.set 90
        local.get 90
        call $free
      end
      local.get 3
      i32.load offset=16
      local.set 91
      local.get 3
      local.get 91
      i32.store offset=28
    end
    local.get 3
    i32.load offset=28
    local.set 92
    i32.const 32
    local.set 93
    local.get 3
    local.get 93
    i32.add
    local.set 94
    local.get 94
    global.set $__stack_pointer
    local.get 92
    return)
  (func $sgx_ecall_copy_information_safe (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 32
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=24
    local.get 3
    i32.load offset=24
    local.set 4
    i32.const 0
    local.set 5
    local.get 4
    local.set 6
    local.get 5
    local.set 7
    local.get 6
    local.get 7
    i32.ne
    local.set 8
    i32.const 1
    local.set 9
    local.get 8
    local.get 9
    i32.and
    local.set 10
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 10
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=24
          local.set 11
          i32.const 8
          local.set 12
          local.get 11
          local.get 12
          call $sgx_is_outside_enclave
          local.set 13
          local.get 13
          br_if 1 (;@2;)
        end
        i32.const 2
        local.set 14
        local.get 3
        local.get 14
        i32.store offset=28
        br 1 (;@1;)
      end
      call $__builtin_ia32_lfence
      local.get 3
      i32.load offset=24
      local.set 15
      local.get 3
      local.get 15
      i32.store offset=20
      i32.const 0
      local.set 16
      local.get 3
      local.get 16
      i32.store offset=16
      local.get 3
      i32.load offset=20
      local.set 17
      local.get 17
      i32.load
      local.set 18
      local.get 3
      local.get 18
      i32.store offset=12
      local.get 3
      i32.load offset=20
      local.set 19
      local.get 19
      i32.load offset=4
      local.set 20
      local.get 3
      local.get 20
      i32.store offset=8
      local.get 3
      i32.load offset=8
      local.set 21
      i32.const 2
      local.set 22
      local.get 21
      local.get 22
      i32.shl
      local.set 23
      local.get 3
      local.get 23
      i32.store offset=4
      i32.const 0
      local.set 24
      local.get 3
      local.get 24
      i32.store
      local.get 3
      i32.load offset=8
      local.set 25
      i32.const 1073741823
      local.set 26
      local.get 25
      local.set 27
      local.get 26
      local.set 28
      local.get 27
      local.get 28
      i32.gt_u
      local.set 29
      i32.const 1
      local.set 30
      local.get 29
      local.get 30
      i32.and
      local.set 31
      block  ;; label = @2
        local.get 31
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2
        local.set 32
        local.get 3
        local.get 32
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=12
      local.set 33
      i32.const 0
      local.set 34
      local.get 33
      local.set 35
      local.get 34
      local.set 36
      local.get 35
      local.get 36
      i32.ne
      local.set 37
      i32.const 1
      local.set 38
      local.get 37
      local.get 38
      i32.and
      local.set 39
      block  ;; label = @2
        local.get 39
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=12
        local.set 40
        local.get 3
        i32.load offset=4
        local.set 41
        local.get 40
        local.get 41
        call $sgx_is_outside_enclave
        local.set 42
        local.get 42
        br_if 0 (;@2;)
        i32.const 2
        local.set 43
        local.get 3
        local.get 43
        i32.store offset=28
        br 1 (;@1;)
      end
      call $__builtin_ia32_lfence
      local.get 3
      i32.load offset=12
      local.set 44
      i32.const 0
      local.set 45
      local.get 44
      local.set 46
      local.get 45
      local.set 47
      local.get 46
      local.get 47
      i32.ne
      local.set 48
      i32.const 1
      local.set 49
      local.get 48
      local.get 49
      i32.and
      local.set 50
      block  ;; label = @2
        block  ;; label = @3
          local.get 50
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=4
          local.set 51
          local.get 51
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=4
          local.set 52
          i32.const 3
          local.set 53
          local.get 52
          local.get 53
          i32.and
          local.set 54
          block  ;; label = @4
            local.get 54
            i32.eqz
            br_if 0 (;@4;)
            i32.const 2
            local.set 55
            local.get 3
            local.get 55
            i32.store offset=16
            br 2 (;@2;)
          end
          local.get 3
          i32.load offset=4
          local.set 56
          local.get 56
          call $malloc
          local.set 57
          local.get 3
          local.get 57
          i32.store
          i32.const 0
          local.set 58
          local.get 57
          local.set 59
          local.get 58
          local.set 60
          local.get 59
          local.get 60
          i32.eq
          local.set 61
          i32.const 1
          local.set 62
          local.get 61
          local.get 62
          i32.and
          local.set 63
          block  ;; label = @4
            local.get 63
            i32.eqz
            br_if 0 (;@4;)
            i32.const 3
            local.set 64
            local.get 3
            local.get 64
            i32.store offset=16
            br 2 (;@2;)
          end
          local.get 3
          i32.load
          local.set 65
          local.get 3
          i32.load offset=4
          local.set 66
          i32.const 0
          local.set 67
          local.get 65
          local.get 67
          local.get 66
          call $memset
          drop
        end
        local.get 3
        i32.load
        local.set 68
        local.get 3
        i32.load offset=8
        local.set 69
        local.get 68
        local.get 69
        call $ecall_copy_information_safe
        local.get 3
        i32.load
        local.set 70
        i32.const 0
        local.set 71
        local.get 70
        local.set 72
        local.get 71
        local.set 73
        local.get 72
        local.get 73
        i32.ne
        local.set 74
        i32.const 1
        local.set 75
        local.get 74
        local.get 75
        i32.and
        local.set 76
        block  ;; label = @3
          local.get 76
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=12
          local.set 77
          local.get 3
          i32.load offset=4
          local.set 78
          local.get 3
          i32.load
          local.set 79
          local.get 3
          i32.load offset=4
          local.set 80
          local.get 77
          local.get 78
          local.get 79
          local.get 80
          call $memcpy_s
          local.set 81
          block  ;; label = @4
            local.get 81
            i32.eqz
            br_if 0 (;@4;)
            i32.const 1
            local.set 82
            local.get 3
            local.get 82
            i32.store offset=16
            br 2 (;@2;)
          end
        end
      end
      local.get 3
      i32.load
      local.set 83
      i32.const 0
      local.set 84
      local.get 83
      local.set 85
      local.get 84
      local.set 86
      local.get 85
      local.get 86
      i32.ne
      local.set 87
      i32.const 1
      local.set 88
      local.get 87
      local.get 88
      i32.and
      local.set 89
      block  ;; label = @2
        local.get 89
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load
        local.set 90
        local.get 90
        call $free
      end
      local.get 3
      i32.load offset=16
      local.set 91
      local.get 3
      local.get 91
      i32.store offset=28
    end
    local.get 3
    i32.load offset=28
    local.set 92
    i32.const 32
    local.set 93
    local.get 3
    local.get 93
    i32.add
    local.set 94
    local.get 94
    global.set $__stack_pointer
    local.get 92
    return)
  (func $ocall_print_string (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 32
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=24
    i32.const 0
    local.set 4
    local.get 3
    local.get 4
    i32.store offset=20
    local.get 3
    i32.load offset=24
    local.set 5
    i32.const 0
    local.set 6
    local.get 5
    local.set 7
    local.get 6
    local.set 8
    local.get 7
    local.get 8
    i32.ne
    local.set 9
    i32.const 1
    local.set 10
    local.get 9
    local.get 10
    i32.and
    local.set 11
    block  ;; label = @1
      block  ;; label = @2
        local.get 11
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=24
        local.set 12
        local.get 12
        call $strlen
        local.set 13
        i32.const 1
        local.set 14
        local.get 13
        local.get 14
        i32.add
        local.set 15
        local.get 15
        local.set 16
        br 1 (;@1;)
      end
      i32.const 0
      local.set 17
      local.get 17
      local.set 16
    end
    local.get 16
    local.set 18
    local.get 3
    local.get 18
    i32.store offset=16
    i32.const 0
    local.set 19
    local.get 3
    local.get 19
    i32.store offset=12
    i32.const 4
    local.set 20
    local.get 3
    local.get 20
    i32.store offset=8
    i32.const 0
    local.set 21
    local.get 3
    local.get 21
    i32.store offset=4
    local.get 3
    i32.load offset=24
    local.set 22
    i32.const 0
    local.set 23
    local.get 22
    local.set 24
    local.get 23
    local.set 25
    local.get 24
    local.get 25
    i32.ne
    local.set 26
    i32.const 1
    local.set 27
    local.get 26
    local.get 27
    i32.and
    local.set 28
    block  ;; label = @1
      block  ;; label = @2
        local.get 28
        i32.eqz
        br_if 0 (;@2;)
        local.get 3
        i32.load offset=24
        local.set 29
        local.get 3
        i32.load offset=16
        local.set 30
        local.get 29
        local.get 30
        call $sgx_is_within_enclave
        local.set 31
        local.get 31
        br_if 0 (;@2;)
        i32.const 2
        local.set 32
        local.get 3
        local.get 32
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=24
      local.set 33
      i32.const 0
      local.set 34
      local.get 33
      local.set 35
      local.get 34
      local.set 36
      local.get 35
      local.get 36
      i32.ne
      local.set 37
      i32.const 1
      local.set 38
      local.get 37
      local.get 38
      i32.and
      local.set 39
      block  ;; label = @2
        block  ;; label = @3
          local.get 39
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=16
          local.set 40
          local.get 40
          local.set 41
          br 1 (;@2;)
        end
        i32.const 0
        local.set 42
        local.get 42
        local.set 41
      end
      local.get 41
      local.set 43
      local.get 3
      i32.load offset=8
      local.set 44
      local.get 44
      local.get 43
      i32.add
      local.set 45
      local.get 3
      local.get 45
      i32.store offset=8
      local.get 3
      i32.load offset=24
      local.set 46
      i32.const 0
      local.set 47
      local.get 46
      local.set 48
      local.get 47
      local.set 49
      local.get 48
      local.get 49
      i32.ne
      local.set 50
      i32.const 1
      local.set 51
      local.get 50
      local.get 51
      i32.and
      local.set 52
      block  ;; label = @2
        block  ;; label = @3
          local.get 52
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=16
          local.set 53
          local.get 53
          local.set 54
          br 1 (;@2;)
        end
        i32.const 0
        local.set 55
        local.get 55
        local.set 54
      end
      local.get 54
      local.set 56
      local.get 45
      local.set 57
      local.get 56
      local.set 58
      local.get 57
      local.get 58
      i32.lt_u
      local.set 59
      i32.const 1
      local.set 60
      local.get 59
      local.get 60
      i32.and
      local.set 61
      block  ;; label = @2
        local.get 61
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2
        local.set 62
        local.get 3
        local.get 62
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=8
      local.set 63
      local.get 63
      call $sgx_ocalloc
      local.set 64
      local.get 3
      local.get 64
      i32.store offset=4
      local.get 3
      i32.load offset=4
      local.set 65
      i32.const 0
      local.set 66
      local.get 65
      local.set 67
      local.get 66
      local.set 68
      local.get 67
      local.get 68
      i32.eq
      local.set 69
      i32.const 1
      local.set 70
      local.get 69
      local.get 70
      i32.and
      local.set 71
      block  ;; label = @2
        local.get 71
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        i32.const 1
        local.set 72
        local.get 3
        local.get 72
        i32.store offset=28
        br 1 (;@1;)
      end
      local.get 3
      i32.load offset=4
      local.set 73
      local.get 3
      local.get 73
      i32.store offset=12
      local.get 3
      i32.load offset=4
      local.set 74
      i32.const 4
      local.set 75
      local.get 74
      local.get 75
      i32.add
      local.set 76
      local.get 3
      local.get 76
      i32.store offset=4
      local.get 3
      i32.load offset=8
      local.set 77
      i32.const 4
      local.set 78
      local.get 77
      local.get 78
      i32.sub
      local.set 79
      local.get 3
      local.get 79
      i32.store offset=8
      local.get 3
      i32.load offset=24
      local.set 80
      i32.const 0
      local.set 81
      local.get 80
      local.set 82
      local.get 81
      local.set 83
      local.get 82
      local.get 83
      i32.ne
      local.set 84
      i32.const 1
      local.set 85
      local.get 84
      local.get 85
      i32.and
      local.set 86
      block  ;; label = @2
        block  ;; label = @3
          local.get 86
          i32.eqz
          br_if 0 (;@3;)
          local.get 3
          i32.load offset=4
          local.set 87
          local.get 3
          i32.load offset=12
          local.set 88
          local.get 88
          local.get 87
          i32.store
          local.get 3
          i32.load offset=16
          local.set 89
          i32.const 0
          local.set 90
          local.get 89
          local.get 90
          i32.and
          local.set 91
          block  ;; label = @4
            local.get 91
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            i32.const 2
            local.set 92
            local.get 3
            local.get 92
            i32.store offset=28
            br 3 (;@1;)
          end
          local.get 3
          i32.load offset=4
          local.set 93
          local.get 3
          i32.load offset=8
          local.set 94
          local.get 3
          i32.load offset=24
          local.set 95
          local.get 3
          i32.load offset=16
          local.set 96
          local.get 93
          local.get 94
          local.get 95
          local.get 96
          call $memcpy_s
          local.set 97
          block  ;; label = @4
            local.get 97
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            i32.const 1
            local.set 98
            local.get 3
            local.get 98
            i32.store offset=28
            br 3 (;@1;)
          end
          local.get 3
          i32.load offset=4
          local.set 99
          local.get 3
          i32.load offset=16
          local.set 100
          local.get 99
          local.get 100
          i32.add
          local.set 101
          local.get 3
          local.get 101
          i32.store offset=4
          local.get 3
          i32.load offset=16
          local.set 102
          local.get 3
          i32.load offset=8
          local.set 103
          local.get 103
          local.get 102
          i32.sub
          local.set 104
          local.get 3
          local.get 104
          i32.store offset=8
          br 1 (;@2;)
        end
        local.get 3
        i32.load offset=12
        local.set 105
        i32.const 0
        local.set 106
        local.get 105
        local.get 106
        i32.store
      end
      local.get 3
      i32.load offset=12
      local.set 107
      i32.const 0
      local.set 108
      local.get 108
      local.get 107
      call $sgx_ocall
      local.set 109
      local.get 3
      local.get 109
      i32.store offset=20
      local.get 3
      i32.load offset=20
      local.set 110
      block  ;; label = @2
        local.get 110
        br_if 0 (;@2;)
      end
      call $sgx_ocfree
      local.get 3
      i32.load offset=20
      local.set 111
      local.get 3
      local.get 111
      i32.store offset=28
    end
    local.get 3
    i32.load offset=28
    local.set 112
    i32.const 32
    local.set 113
    local.get 3
    local.get 113
    i32.add
    local.set 114
    local.get 114
    global.set $__stack_pointer
    local.get 112
    return)
  (func $printf (type 0) (param i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 2
    i32.const 8224
    local.set 3
    local.get 2
    local.get 3
    i32.sub
    local.set 4
    local.get 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=8220
    i32.const 16
    local.set 5
    local.get 4
    local.get 5
    i32.add
    local.set 6
    local.get 6
    local.set 7
    i32.const 8192
    local.set 8
    i32.const 0
    local.set 9
    local.get 7
    local.get 9
    local.get 8
    call $memset
    drop
    i32.const 12
    local.set 10
    local.get 4
    local.get 10
    i32.add
    local.set 11
    local.get 11
    local.set 12
    local.get 12
    local.get 1
    i32.store
    i32.const 16
    local.set 13
    local.get 4
    local.get 13
    i32.add
    local.set 14
    local.get 14
    local.set 15
    local.get 4
    i32.load offset=8220
    local.set 16
    local.get 4
    i32.load offset=12
    local.set 17
    i32.const 8192
    local.set 18
    local.get 15
    local.get 18
    local.get 16
    local.get 17
    call $vsnprintf
    drop
    i32.const 12
    local.set 19
    local.get 4
    local.get 19
    i32.add
    local.set 20
    local.get 20
    drop
    i32.const 16
    local.set 21
    local.get 4
    local.get 21
    i32.add
    local.set 22
    local.get 22
    local.set 23
    local.get 23
    call $ocall_print_string
    drop
    i32.const 16
    local.set 24
    local.get 4
    local.get 24
    i32.add
    local.set 25
    local.get 25
    local.set 26
    i32.const 8191
    local.set 27
    local.get 26
    local.get 27
    call $strnlen
    local.set 28
    i32.const 1
    local.set 29
    local.get 28
    local.get 29
    i32.add
    local.set 30
    i32.const 8224
    local.set 31
    local.get 4
    local.get 31
    i32.add
    local.set 32
    local.get 32
    global.set $__stack_pointer
    local.get 30
    return)
  (func $ecall_copy_information (type 6) (param i32 i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i64 i32 i32 i64 i32 i32 i64 i64 i32 i32 i32 i32 i32 i32 i64 i32 i32 i64 i32 i32 i64 i64 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 2
    i32.const 128
    local.set 3
    local.get 2
    local.get 3
    i32.sub
    local.set 4
    local.get 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=124
    local.get 4
    local.get 1
    i32.store offset=120
    i32.const 80
    local.set 5
    local.get 4
    local.get 5
    i32.add
    local.set 6
    local.get 6
    local.set 7
    i32.const 24
    local.set 8
    local.get 7
    local.get 8
    i32.add
    local.set 9
    i32.const 0
    local.set 10
    local.get 10
    i64.load offset=1080
    local.set 11
    local.get 9
    local.get 11
    i64.store
    i32.const 16
    local.set 12
    local.get 7
    local.get 12
    i32.add
    local.set 13
    local.get 10
    i64.load offset=1072
    local.set 14
    local.get 13
    local.get 14
    i64.store
    i32.const 8
    local.set 15
    local.get 7
    local.get 15
    i32.add
    local.set 16
    local.get 10
    i64.load offset=1064
    local.set 17
    local.get 16
    local.get 17
    i64.store
    local.get 10
    i64.load offset=1056
    local.set 18
    local.get 7
    local.get 18
    i64.store
    i32.const 48
    local.set 19
    local.get 4
    local.get 19
    i32.add
    local.set 20
    local.get 20
    local.set 21
    i32.const 24
    local.set 22
    local.get 21
    local.get 22
    i32.add
    local.set 23
    i32.const 0
    local.set 24
    local.get 24
    i64.load offset=1112
    local.set 25
    local.get 23
    local.get 25
    i64.store
    i32.const 16
    local.set 26
    local.get 21
    local.get 26
    i32.add
    local.set 27
    local.get 24
    i64.load offset=1104
    local.set 28
    local.get 27
    local.get 28
    i64.store
    i32.const 8
    local.set 29
    local.get 21
    local.get 29
    i32.add
    local.set 30
    local.get 24
    i64.load offset=1096
    local.set 31
    local.get 30
    local.get 31
    i64.store
    local.get 24
    i64.load offset=1088
    local.set 32
    local.get 21
    local.get 32
    i64.store
    i32.const 0
    local.set 33
    local.get 33
    i32.load offset=1160
    local.set 34
    local.get 4
    local.get 34
    i32.store
    i32.const 1156
    local.set 35
    local.get 35
    local.get 4
    call $printf
    drop
    i32.const 0
    local.set 36
    local.get 36
    i32.load offset=1160
    local.set 37
    i32.const 1
    local.set 38
    local.get 37
    local.get 38
    i32.add
    local.set 39
    i32.const 0
    local.set 40
    local.get 40
    local.get 39
    i32.store offset=1160
    i32.const 80
    local.set 41
    local.get 4
    local.get 41
    i32.add
    local.set 42
    local.get 42
    local.set 43
    local.get 4
    local.get 43
    i32.store offset=16
    i32.const 1139
    local.set 44
    i32.const 16
    local.set 45
    local.get 4
    local.get 45
    i32.add
    local.set 46
    local.get 44
    local.get 46
    call $printf
    drop
    i32.const 48
    local.set 47
    local.get 4
    local.get 47
    i32.add
    local.set 48
    local.get 48
    local.set 49
    local.get 4
    local.get 49
    i32.store offset=32
    i32.const 1120
    local.set 50
    i32.const 32
    local.set 51
    local.get 4
    local.get 51
    i32.add
    local.set 52
    local.get 50
    local.get 52
    call $printf
    drop
    local.get 4
    i32.load offset=124
    local.set 53
    i32.const 80
    local.set 54
    local.get 4
    local.get 54
    i32.add
    local.set 55
    local.get 55
    local.set 56
    local.get 4
    i32.load offset=120
    local.set 57
    i32.const 2
    local.set 58
    local.get 57
    local.get 58
    i32.shl
    local.set 59
    local.get 53
    local.get 56
    local.get 59
    call $memcpy
    drop
    i32.const 128
    local.set 60
    local.get 4
    local.get 60
    i32.add
    local.set 61
    local.get 61
    global.set $__stack_pointer
    return)
  (func $ecall_copy_information_safe (type 6) (param i32 i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 2
    i32.const 112
    local.set 3
    local.get 2
    local.get 3
    i32.sub
    local.set 4
    local.get 4
    global.set $__stack_pointer
    local.get 4
    local.get 0
    i32.store offset=108
    local.get 4
    local.get 1
    i32.store offset=104
    local.get 4
    i32.load offset=104
    local.set 5
    i32.const 32
    local.set 6
    local.get 4
    local.get 6
    i32.add
    local.set 7
    local.get 7
    local.set 8
    i32.const 2
    local.set 9
    local.get 5
    local.get 9
    i32.shl
    local.set 10
    local.get 8
    local.get 10
    i32.add
    local.set 11
    local.get 11
    i32.load
    local.set 12
    local.get 4
    i32.load offset=104
    local.set 13
    i32.const 64
    local.set 14
    local.get 4
    local.get 14
    i32.add
    local.set 15
    local.get 15
    local.set 16
    i32.const 2
    local.set 17
    local.get 13
    local.get 17
    i32.shl
    local.set 18
    local.get 16
    local.get 18
    i32.add
    local.set 19
    local.get 19
    local.get 12
    i32.store
    i32.const 64
    local.set 20
    local.get 4
    local.get 20
    i32.add
    local.set 21
    local.get 21
    local.set 22
    local.get 4
    local.get 22
    i32.store
    i32.const 1139
    local.set 23
    local.get 23
    local.get 4
    call $printf
    drop
    i32.const 32
    local.set 24
    local.get 4
    local.get 24
    i32.add
    local.set 25
    local.get 25
    local.set 26
    local.get 4
    local.get 26
    i32.store offset=16
    i32.const 1120
    local.set 27
    i32.const 16
    local.set 28
    local.get 4
    local.get 28
    i32.add
    local.set 29
    local.get 27
    local.get 29
    call $printf
    drop
    local.get 4
    i32.load offset=108
    local.set 30
    i32.const 0
    local.set 31
    local.get 30
    local.set 32
    local.get 31
    local.set 33
    local.get 32
    local.get 33
    i32.ne
    local.set 34
    i32.const 1
    local.set 35
    local.get 34
    local.get 35
    i32.and
    local.set 36
    block  ;; label = @1
      block  ;; label = @2
        local.get 36
        br_if 0 (;@2;)
        br 1 (;@1;)
      end
      local.get 4
      i32.load offset=104
      local.set 37
      i32.const 8
      local.set 38
      local.get 37
      local.set 39
      local.get 38
      local.set 40
      local.get 39
      local.get 40
      i32.gt_u
      local.set 41
      i32.const 1
      local.set 42
      local.get 41
      local.get 42
      i32.and
      local.set 43
      block  ;; label = @2
        block  ;; label = @3
          local.get 43
          i32.eqz
          br_if 0 (;@3;)
          i32.const 8
          local.set 44
          local.get 44
          local.set 45
          br 1 (;@2;)
        end
        local.get 4
        i32.load offset=104
        local.set 46
        local.get 46
        local.set 45
      end
      local.get 45
      local.set 47
      local.get 4
      local.get 47
      i32.store offset=104
      local.get 4
      i32.load offset=108
      local.set 48
      i32.const 64
      local.set 49
      local.get 4
      local.get 49
      i32.add
      local.set 50
      local.get 50
      local.set 51
      local.get 4
      i32.load offset=104
      local.set 52
      i32.const 2
      local.set 53
      local.get 52
      local.get 53
      i32.shl
      local.set 54
      local.get 48
      local.get 51
      local.get 54
      call $memcpy
      drop
    end
    i32.const 112
    local.set 55
    local.get 4
    local.get 55
    i32.add
    local.set 56
    local.get 56
    global.set $__stack_pointer
    return)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66704))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1044))
  (global (;3;) i32 (i32.const 1160))
  (global (;4;) i32 (i32.const 1024))
  (global (;5;) i32 (i32.const 1164))
  (global (;6;) i32 (i32.const 1024))
  (global (;7;) i32 (i32.const 66704))
  (global (;8;) i32 (i32.const 0))
  (global (;9;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "sgx_ecall_copy_information" (func $sgx_ecall_copy_information))
  (export "ecall_copy_information" (func $ecall_copy_information))
  (export "sgx_ecall_copy_information_safe" (func $sgx_ecall_copy_information_safe))
  (export "ecall_copy_information_safe" (func $ecall_copy_information_safe))
  (export "ocall_print_string" (func $ocall_print_string))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "printf" (func $printf))
  (export "global_int" (global 3))
  (export "__dso_handle" (global 4))
  (export "__data_end" (global 5))
  (export "__global_base" (global 6))
  (export "__heap_base" (global 7))
  (export "__memory_base" (global 8))
  (export "__table_base" (global 9))
  (data $.rodata (i32.const 1024) "\02\00\00\00i\1e\0f\00\00\00\00\00i\1e\0f\00\00\00\00\00\01\00\00\00\00\00\00\00\00\00\00\00\0f\00\00\00\0f\00\00\00\0f\00\00\00\0f\00\00\00\0f\00\00\00\0f\00\00\00\0f\00\00\00\0f\00\00\00\01\00\00\00\02\00\00\00\03\00\00\00\04\00\00\00\05\00\00\00\06\00\00\00\07\00\00\00\08\00\00\00secret address %p\0a\00meta address %p\0a\00%d\0a\00")
  (data $.data (i32.const 1160) "\03\00\00\00"))
