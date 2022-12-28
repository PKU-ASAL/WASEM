(module
  (type (;0;) (func (param i32 i32) (result i32)))
  (type (;1;) (func))
  (type (;2;) (func (param i32) (result i32)))
  (type (;3;) (func (param i32 i32 i32 i32) (result i32)))
  (type (;4;) (func (param i32 i32 i32) (result i32)))
  (type (;5;) (func (param i32 i32 i32 i32 i32) (result i32)))
  (type (;6;) (func (result i32)))
  (import "env" "sgx_is_outside_enclave" (func $sgx_is_outside_enclave (type 0)))
  (import "env" "__builtin_ia32_lfence" (func $__builtin_ia32_lfence (type 1)))
  (import "env" "sgx_ocalloc" (func $sgx_ocalloc (type 2)))
  (import "env" "sgx_ocfree" (func $sgx_ocfree (type 1)))
  (import "env" "sgx_ocall" (func $sgx_ocall (type 0)))
  (import "env" "sgx_is_within_enclave" (func $sgx_is_within_enclave (type 0)))
  (import "env" "memcpy_s" (func $memcpy_s (type 3)))
  (import "env" "memset" (func $memset (type 4)))
  (func $__wasm_call_ctors (type 1))
  (func $sgx_my_ecall (type 2) (param i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 1
    i32.const 16
    local.set 2
    local.get 1
    local.get 2
    i32.sub
    local.set 3
    local.get 3
    global.set $__stack_pointer
    local.get 3
    local.get 0
    i32.store offset=8
    local.get 3
    i32.load offset=8
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
          i32.load offset=8
          local.set 11
          i32.const 4
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
        i32.store offset=12
        br 1 (;@1;)
      end
      call $__builtin_ia32_lfence
      local.get 3
      i32.load offset=8
      local.set 15
      local.get 3
      local.get 15
      i32.store offset=4
      i32.const 0
      local.set 16
      local.get 3
      local.get 16
      i32.store
      call $my_ecall
      local.set 17
      local.get 3
      i32.load offset=4
      local.set 18
      local.get 18
      local.get 17
      i32.store
      local.get 3
      i32.load
      local.set 19
      local.get 3
      local.get 19
      i32.store offset=12
    end
    local.get 3
    i32.load offset=12
    local.set 20
    i32.const 16
    local.set 21
    local.get 3
    local.get 21
    i32.add
    local.set 22
    local.get 22
    global.set $__stack_pointer
    local.get 20
    return)
  (func $socket_ocall (type 3) (param i32 i32 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 4
    i32.const 48
    local.set 5
    local.get 4
    local.get 5
    i32.sub
    local.set 6
    local.get 6
    global.set $__stack_pointer
    local.get 6
    local.get 0
    i32.store offset=40
    local.get 6
    local.get 1
    i32.store offset=36
    local.get 6
    local.get 2
    i32.store offset=32
    local.get 6
    local.get 3
    i32.store offset=28
    i32.const 0
    local.set 7
    local.get 6
    local.get 7
    i32.store offset=24
    i32.const 0
    local.set 8
    local.get 6
    local.get 8
    i32.store offset=20
    i32.const 16
    local.set 9
    local.get 6
    local.get 9
    i32.store offset=16
    i32.const 0
    local.set 10
    local.get 6
    local.get 10
    i32.store offset=12
    local.get 6
    i32.load offset=16
    local.set 11
    local.get 11
    call $sgx_ocalloc
    local.set 12
    local.get 6
    local.get 12
    i32.store offset=12
    local.get 6
    i32.load offset=12
    local.set 13
    i32.const 0
    local.set 14
    local.get 13
    local.set 15
    local.get 14
    local.set 16
    local.get 15
    local.get 16
    i32.eq
    local.set 17
    i32.const 1
    local.set 18
    local.get 17
    local.get 18
    i32.and
    local.set 19
    block  ;; label = @1
      block  ;; label = @2
        local.get 19
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        i32.const 1
        local.set 20
        local.get 6
        local.get 20
        i32.store offset=44
        br 1 (;@1;)
      end
      local.get 6
      i32.load offset=12
      local.set 21
      local.get 6
      local.get 21
      i32.store offset=20
      local.get 6
      i32.load offset=12
      local.set 22
      i32.const 16
      local.set 23
      local.get 22
      local.get 23
      i32.add
      local.set 24
      local.get 6
      local.get 24
      i32.store offset=12
      local.get 6
      i32.load offset=16
      local.set 25
      i32.const 16
      local.set 26
      local.get 25
      local.get 26
      i32.sub
      local.set 27
      local.get 6
      local.get 27
      i32.store offset=16
      local.get 6
      i32.load offset=36
      local.set 28
      local.get 6
      i32.load offset=20
      local.set 29
      local.get 29
      local.get 28
      i32.store offset=4
      local.get 6
      i32.load offset=32
      local.set 30
      local.get 6
      i32.load offset=20
      local.set 31
      local.get 31
      local.get 30
      i32.store offset=8
      local.get 6
      i32.load offset=28
      local.set 32
      local.get 6
      i32.load offset=20
      local.set 33
      local.get 33
      local.get 32
      i32.store offset=12
      local.get 6
      i32.load offset=20
      local.set 34
      i32.const 0
      local.set 35
      local.get 35
      local.get 34
      call $sgx_ocall
      local.set 36
      local.get 6
      local.get 36
      i32.store offset=24
      local.get 6
      i32.load offset=24
      local.set 37
      block  ;; label = @2
        local.get 37
        br_if 0 (;@2;)
        local.get 6
        i32.load offset=40
        local.set 38
        i32.const 0
        local.set 39
        local.get 38
        local.set 40
        local.get 39
        local.set 41
        local.get 40
        local.get 41
        i32.ne
        local.set 42
        i32.const 1
        local.set 43
        local.get 42
        local.get 43
        i32.and
        local.set 44
        block  ;; label = @3
          local.get 44
          i32.eqz
          br_if 0 (;@3;)
          local.get 6
          i32.load offset=20
          local.set 45
          local.get 45
          i32.load
          local.set 46
          local.get 6
          i32.load offset=40
          local.set 47
          local.get 47
          local.get 46
          i32.store
        end
      end
      call $sgx_ocfree
      local.get 6
      i32.load offset=24
      local.set 48
      local.get 6
      local.get 48
      i32.store offset=44
    end
    local.get 6
    i32.load offset=44
    local.set 49
    i32.const 48
    local.set 50
    local.get 6
    local.get 50
    i32.add
    local.set 51
    local.get 51
    global.set $__stack_pointer
    local.get 49
    return)
  (func $getpeername_ocall (type 5) (param i32 i32 i32 i32 i32) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 5
    i32.const 64
    local.set 6
    local.get 5
    local.get 6
    i32.sub
    local.set 7
    local.get 7
    global.set $__stack_pointer
    local.get 7
    local.get 0
    i32.store offset=56
    local.get 7
    local.get 1
    i32.store offset=52
    local.get 7
    local.get 2
    i32.store offset=48
    local.get 7
    local.get 3
    i32.store offset=44
    local.get 7
    local.get 4
    i32.store offset=40
    i32.const 0
    local.set 8
    local.get 7
    local.get 8
    i32.store offset=36
    local.get 7
    i32.load offset=44
    local.set 9
    local.get 7
    local.get 9
    i32.store offset=32
    i32.const 4
    local.set 10
    local.get 7
    local.get 10
    i32.store offset=28
    i32.const 0
    local.set 11
    local.get 7
    local.get 11
    i32.store offset=24
    i32.const 20
    local.set 12
    local.get 7
    local.get 12
    i32.store offset=20
    i32.const 0
    local.set 13
    local.get 7
    local.get 13
    i32.store offset=16
    i32.const 0
    local.set 14
    local.get 7
    local.get 14
    i32.store offset=12
    i32.const 0
    local.set 15
    local.get 7
    local.get 15
    i32.store offset=8
    local.get 7
    i32.load offset=48
    local.set 16
    i32.const 0
    local.set 17
    local.get 16
    local.set 18
    local.get 17
    local.set 19
    local.get 18
    local.get 19
    i32.ne
    local.set 20
    i32.const 1
    local.set 21
    local.get 20
    local.get 21
    i32.and
    local.set 22
    block  ;; label = @1
      block  ;; label = @2
        local.get 22
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        i32.load offset=48
        local.set 23
        local.get 7
        i32.load offset=32
        local.set 24
        local.get 23
        local.get 24
        call $sgx_is_within_enclave
        local.set 25
        local.get 25
        br_if 0 (;@2;)
        i32.const 2
        local.set 26
        local.get 7
        local.get 26
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 7
      i32.load offset=40
      local.set 27
      i32.const 0
      local.set 28
      local.get 27
      local.set 29
      local.get 28
      local.set 30
      local.get 29
      local.get 30
      i32.ne
      local.set 31
      i32.const 1
      local.set 32
      local.get 31
      local.get 32
      i32.and
      local.set 33
      block  ;; label = @2
        local.get 33
        i32.eqz
        br_if 0 (;@2;)
        local.get 7
        i32.load offset=40
        local.set 34
        local.get 7
        i32.load offset=28
        local.set 35
        local.get 34
        local.get 35
        call $sgx_is_within_enclave
        local.set 36
        local.get 36
        br_if 0 (;@2;)
        i32.const 2
        local.set 37
        local.get 7
        local.get 37
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 7
      i32.load offset=48
      local.set 38
      i32.const 0
      local.set 39
      local.get 38
      local.set 40
      local.get 39
      local.set 41
      local.get 40
      local.get 41
      i32.ne
      local.set 42
      i32.const 1
      local.set 43
      local.get 42
      local.get 43
      i32.and
      local.set 44
      block  ;; label = @2
        block  ;; label = @3
          local.get 44
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=32
          local.set 45
          local.get 45
          local.set 46
          br 1 (;@2;)
        end
        i32.const 0
        local.set 47
        local.get 47
        local.set 46
      end
      local.get 46
      local.set 48
      local.get 7
      i32.load offset=20
      local.set 49
      local.get 49
      local.get 48
      i32.add
      local.set 50
      local.get 7
      local.get 50
      i32.store offset=20
      local.get 7
      i32.load offset=48
      local.set 51
      i32.const 0
      local.set 52
      local.get 51
      local.set 53
      local.get 52
      local.set 54
      local.get 53
      local.get 54
      i32.ne
      local.set 55
      i32.const 1
      local.set 56
      local.get 55
      local.get 56
      i32.and
      local.set 57
      block  ;; label = @2
        block  ;; label = @3
          local.get 57
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=32
          local.set 58
          local.get 58
          local.set 59
          br 1 (;@2;)
        end
        i32.const 0
        local.set 60
        local.get 60
        local.set 59
      end
      local.get 59
      local.set 61
      local.get 50
      local.set 62
      local.get 61
      local.set 63
      local.get 62
      local.get 63
      i32.lt_u
      local.set 64
      i32.const 1
      local.set 65
      local.get 64
      local.get 65
      i32.and
      local.set 66
      block  ;; label = @2
        local.get 66
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2
        local.set 67
        local.get 7
        local.get 67
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 7
      i32.load offset=40
      local.set 68
      i32.const 0
      local.set 69
      local.get 68
      local.set 70
      local.get 69
      local.set 71
      local.get 70
      local.get 71
      i32.ne
      local.set 72
      i32.const 1
      local.set 73
      local.get 72
      local.get 73
      i32.and
      local.set 74
      block  ;; label = @2
        block  ;; label = @3
          local.get 74
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=28
          local.set 75
          local.get 75
          local.set 76
          br 1 (;@2;)
        end
        i32.const 0
        local.set 77
        local.get 77
        local.set 76
      end
      local.get 76
      local.set 78
      local.get 7
      i32.load offset=20
      local.set 79
      local.get 79
      local.get 78
      i32.add
      local.set 80
      local.get 7
      local.get 80
      i32.store offset=20
      local.get 7
      i32.load offset=40
      local.set 81
      i32.const 0
      local.set 82
      local.get 81
      local.set 83
      local.get 82
      local.set 84
      local.get 83
      local.get 84
      i32.ne
      local.set 85
      i32.const 1
      local.set 86
      local.get 85
      local.get 86
      i32.and
      local.set 87
      block  ;; label = @2
        block  ;; label = @3
          local.get 87
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=28
          local.set 88
          local.get 88
          local.set 89
          br 1 (;@2;)
        end
        i32.const 0
        local.set 90
        local.get 90
        local.set 89
      end
      local.get 89
      local.set 91
      local.get 80
      local.set 92
      local.get 91
      local.set 93
      local.get 92
      local.get 93
      i32.lt_u
      local.set 94
      i32.const 1
      local.set 95
      local.get 94
      local.get 95
      i32.and
      local.set 96
      block  ;; label = @2
        local.get 96
        i32.eqz
        br_if 0 (;@2;)
        i32.const 2
        local.set 97
        local.get 7
        local.get 97
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 7
      i32.load offset=20
      local.set 98
      local.get 98
      call $sgx_ocalloc
      local.set 99
      local.get 7
      local.get 99
      i32.store offset=16
      local.get 7
      i32.load offset=16
      local.set 100
      i32.const 0
      local.set 101
      local.get 100
      local.set 102
      local.get 101
      local.set 103
      local.get 102
      local.get 103
      i32.eq
      local.set 104
      i32.const 1
      local.set 105
      local.get 104
      local.get 105
      i32.and
      local.set 106
      block  ;; label = @2
        local.get 106
        i32.eqz
        br_if 0 (;@2;)
        call $sgx_ocfree
        i32.const 1
        local.set 107
        local.get 7
        local.get 107
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 7
      i32.load offset=16
      local.set 108
      local.get 7
      local.get 108
      i32.store offset=24
      local.get 7
      i32.load offset=16
      local.set 109
      i32.const 20
      local.set 110
      local.get 109
      local.get 110
      i32.add
      local.set 111
      local.get 7
      local.get 111
      i32.store offset=16
      local.get 7
      i32.load offset=20
      local.set 112
      i32.const 20
      local.set 113
      local.get 112
      local.get 113
      i32.sub
      local.set 114
      local.get 7
      local.get 114
      i32.store offset=20
      local.get 7
      i32.load offset=52
      local.set 115
      local.get 7
      i32.load offset=24
      local.set 116
      local.get 116
      local.get 115
      i32.store offset=4
      local.get 7
      i32.load offset=48
      local.set 117
      i32.const 0
      local.set 118
      local.get 117
      local.set 119
      local.get 118
      local.set 120
      local.get 119
      local.get 120
      i32.ne
      local.set 121
      i32.const 1
      local.set 122
      local.get 121
      local.get 122
      i32.and
      local.set 123
      block  ;; label = @2
        block  ;; label = @3
          local.get 123
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=16
          local.set 124
          local.get 7
          i32.load offset=24
          local.set 125
          local.get 125
          local.get 124
          i32.store offset=8
          local.get 7
          i32.load offset=16
          local.set 126
          local.get 7
          local.get 126
          i32.store offset=12
          local.get 7
          i32.load offset=16
          local.set 127
          local.get 7
          i32.load offset=20
          local.set 128
          local.get 7
          i32.load offset=48
          local.set 129
          local.get 7
          i32.load offset=32
          local.set 130
          local.get 127
          local.get 128
          local.get 129
          local.get 130
          call $memcpy_s
          local.set 131
          block  ;; label = @4
            local.get 131
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            i32.const 1
            local.set 132
            local.get 7
            local.get 132
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 7
          i32.load offset=16
          local.set 133
          local.get 7
          i32.load offset=32
          local.set 134
          local.get 133
          local.get 134
          i32.add
          local.set 135
          local.get 7
          local.get 135
          i32.store offset=16
          local.get 7
          i32.load offset=32
          local.set 136
          local.get 7
          i32.load offset=20
          local.set 137
          local.get 137
          local.get 136
          i32.sub
          local.set 138
          local.get 7
          local.get 138
          i32.store offset=20
          br 1 (;@2;)
        end
        local.get 7
        i32.load offset=24
        local.set 139
        i32.const 0
        local.set 140
        local.get 139
        local.get 140
        i32.store offset=8
      end
      local.get 7
      i32.load offset=44
      local.set 141
      local.get 7
      i32.load offset=24
      local.set 142
      local.get 142
      local.get 141
      i32.store offset=12
      local.get 7
      i32.load offset=40
      local.set 143
      i32.const 0
      local.set 144
      local.get 143
      local.set 145
      local.get 144
      local.set 146
      local.get 145
      local.get 146
      i32.ne
      local.set 147
      i32.const 1
      local.set 148
      local.get 147
      local.get 148
      i32.and
      local.set 149
      block  ;; label = @2
        block  ;; label = @3
          local.get 149
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=16
          local.set 150
          local.get 7
          i32.load offset=24
          local.set 151
          local.get 151
          local.get 150
          i32.store offset=16
          local.get 7
          i32.load offset=16
          local.set 152
          local.get 7
          local.get 152
          i32.store offset=8
          local.get 7
          i32.load offset=28
          local.set 153
          i32.const 3
          local.set 154
          local.get 153
          local.get 154
          i32.and
          local.set 155
          block  ;; label = @4
            local.get 155
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            i32.const 2
            local.set 156
            local.get 7
            local.get 156
            i32.store offset=60
            br 3 (;@1;)
          end
          local.get 7
          i32.load offset=8
          local.set 157
          local.get 7
          i32.load offset=28
          local.set 158
          i32.const 0
          local.set 159
          local.get 157
          local.get 159
          local.get 158
          call $memset
          drop
          local.get 7
          i32.load offset=16
          local.set 160
          local.get 7
          i32.load offset=28
          local.set 161
          local.get 160
          local.get 161
          i32.add
          local.set 162
          local.get 7
          local.get 162
          i32.store offset=16
          local.get 7
          i32.load offset=28
          local.set 163
          local.get 7
          i32.load offset=20
          local.set 164
          local.get 164
          local.get 163
          i32.sub
          local.set 165
          local.get 7
          local.get 165
          i32.store offset=20
          br 1 (;@2;)
        end
        local.get 7
        i32.load offset=24
        local.set 166
        i32.const 0
        local.set 167
        local.get 166
        local.get 167
        i32.store offset=16
      end
      local.get 7
      i32.load offset=24
      local.set 168
      i32.const 1
      local.set 169
      local.get 169
      local.get 168
      call $sgx_ocall
      local.set 170
      local.get 7
      local.get 170
      i32.store offset=36
      local.get 7
      i32.load offset=36
      local.set 171
      block  ;; label = @2
        local.get 171
        br_if 0 (;@2;)
        local.get 7
        i32.load offset=56
        local.set 172
        i32.const 0
        local.set 173
        local.get 172
        local.set 174
        local.get 173
        local.set 175
        local.get 174
        local.get 175
        i32.ne
        local.set 176
        i32.const 1
        local.set 177
        local.get 176
        local.get 177
        i32.and
        local.set 178
        block  ;; label = @3
          local.get 178
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=24
          local.set 179
          local.get 179
          i32.load
          local.set 180
          local.get 7
          i32.load offset=56
          local.set 181
          local.get 181
          local.get 180
          i32.store
        end
        local.get 7
        i32.load offset=48
        local.set 182
        i32.const 0
        local.set 183
        local.get 182
        local.set 184
        local.get 183
        local.set 185
        local.get 184
        local.get 185
        i32.ne
        local.set 186
        i32.const 1
        local.set 187
        local.get 186
        local.get 187
        i32.and
        local.set 188
        block  ;; label = @3
          local.get 188
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=48
          local.set 189
          local.get 7
          i32.load offset=32
          local.set 190
          local.get 7
          i32.load offset=12
          local.set 191
          local.get 7
          i32.load offset=32
          local.set 192
          local.get 189
          local.get 190
          local.get 191
          local.get 192
          call $memcpy_s
          local.set 193
          block  ;; label = @4
            local.get 193
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            i32.const 1
            local.set 194
            local.get 7
            local.get 194
            i32.store offset=60
            br 3 (;@1;)
          end
        end
        local.get 7
        i32.load offset=40
        local.set 195
        i32.const 0
        local.set 196
        local.get 195
        local.set 197
        local.get 196
        local.set 198
        local.get 197
        local.get 198
        i32.ne
        local.set 199
        i32.const 1
        local.set 200
        local.get 199
        local.get 200
        i32.and
        local.set 201
        block  ;; label = @3
          local.get 201
          i32.eqz
          br_if 0 (;@3;)
          local.get 7
          i32.load offset=40
          local.set 202
          local.get 7
          i32.load offset=28
          local.set 203
          local.get 7
          i32.load offset=8
          local.set 204
          local.get 7
          i32.load offset=28
          local.set 205
          local.get 202
          local.get 203
          local.get 204
          local.get 205
          call $memcpy_s
          local.set 206
          block  ;; label = @4
            local.get 206
            i32.eqz
            br_if 0 (;@4;)
            call $sgx_ocfree
            i32.const 1
            local.set 207
            local.get 7
            local.get 207
            i32.store offset=60
            br 3 (;@1;)
          end
        end
      end
      call $sgx_ocfree
      local.get 7
      i32.load offset=36
      local.set 208
      local.get 7
      local.get 208
      i32.store offset=60
    end
    local.get 7
    i32.load offset=60
    local.set 209
    i32.const 64
    local.set 210
    local.get 7
    local.get 210
    i32.add
    local.set 211
    local.get 211
    global.set $__stack_pointer
    local.get 209
    return)
  (func $my_ecall (type 6) (result i32)
    (local i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32)
    global.get $__stack_pointer
    local.set 0
    i32.const 64
    local.set 1
    local.get 0
    local.get 1
    i32.sub
    local.set 2
    local.get 2
    global.set $__stack_pointer
    i32.const 0
    local.set 3
    local.get 2
    local.get 3
    i32.store offset=56
    i32.const 0
    local.set 4
    local.get 2
    local.get 4
    i32.store offset=52
    i32.const 0
    local.set 5
    local.get 2
    local.get 5
    i32.store offset=48
    i32.const 2
    local.set 6
    local.get 2
    local.get 6
    i32.store offset=44
    i32.const 1
    local.set 7
    local.get 2
    local.get 7
    i32.store offset=40
    i32.const 0
    local.set 8
    local.get 2
    local.get 8
    i32.store offset=36
    i32.const 16
    local.set 9
    local.get 2
    local.get 9
    i32.store offset=8
    local.get 2
    i32.load offset=8
    local.set 10
    local.get 2
    local.get 10
    i32.store offset=12
    local.get 2
    i32.load offset=44
    local.set 11
    local.get 2
    i32.load offset=40
    local.set 12
    local.get 2
    i32.load offset=36
    local.set 13
    i32.const 48
    local.set 14
    local.get 2
    local.get 14
    i32.add
    local.set 15
    local.get 15
    local.set 16
    local.get 16
    local.get 11
    local.get 12
    local.get 13
    call $socket_ocall
    local.set 17
    local.get 2
    local.get 17
    i32.store offset=56
    local.get 2
    i32.load offset=56
    local.set 18
    block  ;; label = @1
      block  ;; label = @2
        block  ;; label = @3
          local.get 18
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=48
          local.set 19
          i32.const -1
          local.set 20
          local.get 19
          local.set 21
          local.get 20
          local.set 22
          local.get 21
          local.get 22
          i32.eq
          local.set 23
          i32.const 1
          local.set 24
          local.get 23
          local.get 24
          i32.and
          local.set 25
          local.get 25
          i32.eqz
          br_if 1 (;@2;)
        end
        i32.const -1
        local.set 26
        local.get 2
        local.get 26
        i32.store offset=60
        br 1 (;@1;)
      end
      i32.const 16
      local.set 27
      local.get 2
      local.get 27
      i32.add
      local.set 28
      local.get 28
      local.set 29
      local.get 2
      i32.load offset=8
      local.set 30
      local.get 29
      local.get 30
      i32.add
      local.set 31
      i32.const -1
      local.set 32
      local.get 31
      local.get 32
      i32.add
      local.set 33
      i32.const 2
      local.set 34
      local.get 33
      local.get 34
      i32.store8
      local.get 2
      i32.load offset=48
      local.set 35
      local.get 2
      i32.load offset=12
      local.set 36
      i32.const 52
      local.set 37
      local.get 2
      local.get 37
      i32.add
      local.set 38
      local.get 38
      local.set 39
      i32.const 16
      local.set 40
      local.get 2
      local.get 40
      i32.add
      local.set 41
      local.get 41
      local.set 42
      i32.const 8
      local.set 43
      local.get 2
      local.get 43
      i32.add
      local.set 44
      local.get 44
      local.set 45
      local.get 39
      local.get 35
      local.get 42
      local.get 36
      local.get 45
      call $getpeername_ocall
      local.set 46
      local.get 2
      local.get 46
      i32.store offset=56
      block  ;; label = @2
        block  ;; label = @3
          local.get 46
          br_if 0 (;@3;)
          local.get 2
          i32.load offset=52
          local.set 47
          i32.const -1
          local.set 48
          local.get 47
          local.set 49
          local.get 48
          local.set 50
          local.get 49
          local.get 50
          i32.eq
          local.set 51
          i32.const 1
          local.set 52
          local.get 51
          local.get 52
          i32.and
          local.set 53
          local.get 53
          i32.eqz
          br_if 1 (;@2;)
        end
        i32.const -1
        local.set 54
        local.get 2
        local.get 54
        i32.store offset=60
        br 1 (;@1;)
      end
      local.get 2
      i32.load offset=48
      local.set 55
      i32.const 10
      local.set 56
      local.get 55
      local.get 56
      i32.add
      local.set 57
      local.get 2
      local.get 57
      i32.store offset=40
      local.get 2
      i32.load offset=8
      local.set 58
      local.get 2
      local.get 58
      i32.store offset=12
      local.get 2
      i32.load offset=12
      local.set 59
      i32.const 0
      local.set 60
      local.get 59
      local.set 61
      local.get 60
      local.set 62
      local.get 61
      local.get 62
      i32.le_u
      local.set 63
      i32.const 1
      local.set 64
      local.get 63
      local.get 64
      i32.and
      local.set 65
      block  ;; label = @2
        local.get 65
        i32.eqz
        br_if 0 (;@2;)
        i32.const -1
        local.set 66
        local.get 2
        local.get 66
        i32.store offset=60
        br 1 (;@1;)
      end
      i32.const 16
      local.set 67
      local.get 2
      local.get 67
      i32.add
      local.set 68
      local.get 68
      local.set 69
      local.get 2
      i32.load offset=8
      local.set 70
      local.get 69
      local.get 70
      i32.add
      local.set 71
      i32.const -1
      local.set 72
      local.get 71
      local.get 72
      i32.add
      local.set 73
      local.get 73
      i32.load8_u
      local.set 74
      i32.const 24
      local.set 75
      local.get 74
      local.get 75
      i32.shl
      local.set 76
      local.get 76
      local.get 75
      i32.shr_s
      local.set 77
      local.get 2
      local.get 77
      i32.store offset=48
      i32.const 0
      local.set 78
      local.get 2
      local.get 78
      i32.store offset=60
    end
    local.get 2
    i32.load offset=60
    local.set 79
    i32.const 64
    local.set 80
    local.get 2
    local.get 80
    i32.add
    local.set 81
    local.get 81
    global.set $__stack_pointer
    local.get 79
    return)
  (memory (;0;) 2)
  (global $__stack_pointer (mut i32) (i32.const 66592))
  (global (;1;) i32 (i32.const 1024))
  (global (;2;) i32 (i32.const 1036))
  (global (;3;) i32 (i32.const 1024))
  (global (;4;) i32 (i32.const 1044))
  (global (;5;) i32 (i32.const 1024))
  (global (;6;) i32 (i32.const 66592))
  (global (;7;) i32 (i32.const 0))
  (global (;8;) i32 (i32.const 1))
  (export "memory" (memory 0))
  (export "__wasm_call_ctors" (func $__wasm_call_ctors))
  (export "sgx_my_ecall" (func $sgx_my_ecall))
  (export "my_ecall" (func $my_ecall))
  (export "socket_ocall" (func $socket_ocall))
  (export "getpeername_ocall" (func $getpeername_ocall))
  (export "g_ecall_table" (global 1))
  (export "g_dyn_entry_table" (global 2))
  (export "__dso_handle" (global 3))
  (export "__data_end" (global 4))
  (export "__global_base" (global 5))
  (export "__heap_base" (global 6))
  (export "__memory_base" (global 7))
  (export "__table_base" (global 8))
  (data $.rodata (i32.const 1024) "\01\00\00\00\00\00\00\00\00\00\00\00\02\00\00\00\00\00\00\00"))
