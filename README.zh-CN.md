# TLS-Session

[English](README.md) | [中文](README.zh-CN.md)

[![Latest Version](https://img.shields.io/packagist/v/tourze/tls-session.svg?style=flat-square)]
(https://packagist.org/packages/tourze/tls-session)
[![PHP Version](https://img.shields.io/packagist/php-v/tourze/tls-session.svg?style=flat-square)]
(https://packagist.org/packages/tourze/tls-session)
[![License](https://img.shields.io/packagist/l/tourze/tls-session.svg?style=flat-square)]
(https://packagist.org/packages/tourze/tls-session)
[![Build Status](https://img.shields.io/github/actions/workflow/status/tourze/tls-session/ci.yml?branch=master&style=flat-square)]
(https://github.com/tourze/tls-session/actions)
[![Quality Score](https://img.shields.io/scrutinizer/g/tourze/tls-session.svg?style=flat-square)]
(https://scrutinizer-ci.com/g/tourze/tls-session)
[![Code Coverage](https://img.shields.io/scrutinizer/coverage/g/tourze/tls-session.svg?style=flat-square)]
(https://scrutinizer-ci.com/g/tourze/tls-session)
[![Total Downloads](https://img.shields.io/packagist/dt/tourze/tls-session.svg?style=flat-square)]
(https://packagist.org/packages/tourze/tls-session)

一个用于TLS会话管理和维护的PHP库，提供TLS 1.2和TLS 1.3协议的全面会话处理、
票据管理和恢复功能。

## 目录

- [功能特性](#功能特性)
- [安装](#安装)
- [快速开始](#快速开始)
- [高级用法](#高级用法)
- [系统要求](#系统要求)
- [API 文档](#api-文档)
- [测试](#测试)
- [贡献](#贡献)
- [许可证](#许可证)

## 功能特性

- **会话管理**: 创建、存储和检索TLS会话
- **会话票据**: 生成、加密和解密会话票据
- **会话恢复**: 支持TLS会话恢复功能
- **TLS 1.3 PSK会话**: 支持早期数据的预共享密钥会话
- **会话安全**: 安全的会话验证和清理
- **密钥管理**: 自动密钥轮换和管理
- **内存缓存**: 内存会话存储实现
- **会话超时**: 自动过期和清理
- **0-RTT数据**: 支持TLS 1.3 0-RTT数据传输
- **跨连接**: 跨连接的会话数据处理

## 安装

```bash
composer require tourze/tls-session
```

## 快速开始

### 基础会话管理

```php
<?php

use Tourze\TLSSession\InMemorySessionManager;
use Tourze\TLSSession\TLSSession;

// 创建会话管理器
$sessionManager = new InMemorySessionManager();

// 创建新会话
$session = $sessionManager->createSession(
    'TLS_AES_256_GCM_SHA384',
    'master_secret_here'
);

// 存储会话
$sessionManager->storeSession($session);

// 通过ID检索会话
$retrievedSession = $sessionManager->getSessionById($session->getSessionId());

// 清理过期会话
$cleanedCount = $sessionManager->cleanExpiredSessions();
```

### 会话票据管理

```php
<?php

use Tourze\TLSSession\SessionTicketManager;
use Tourze\TLSSession\TLSSession;

// 创建票据管理器
$ticketManager = new SessionTicketManager();

// 创建会话
$session = new TLSSession(
    sessionId: 'session_123',
    masterSecret: 'secret_key',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    tlsVersion: 0x0303
);

// 创建会话票据
$ticket = $ticketManager->createTicket($session);

// 解密票据以恢复会话
$restoredSession = $ticketManager->decryptTicket($ticket);
```

### TLS 1.3 PSK 会话

```php
<?php

use Tourze\TLSSession\TLS13PSKSession;
use Tourze\TLSSession\TLS13PSKSessionManager;

// 创建 PSK 会话管理器
$pskManager = new TLS13PSKSessionManager();

// 创建支持早期数据的 PSK 会话
$pskSession = new TLS13PSKSession(
    sessionId: 'psk_session_123',
    cipherSuite: 0x1301, // TLS_AES_128_GCM_SHA256
    masterSecret: 'psk_secret',
    pskIdentity: 'client_identity',
    ticketNonce: 'nonce_value'
);

// 启用早期数据
$pskSession->setMaxEarlyDataSize(4096);

// 存储 PSK 会话
$pskManager->storeSession($pskSession);
```

### 会话安全验证

```php
<?php

use Tourze\TLSSession\SessionSecurityValidator;
use Tourze\TLSSession\TLSSession;

// 创建验证器
$validator = new SessionSecurityValidator();

// 验证 TLS 1.2 会话安全性
$session = new TLSSession(
    sessionId: 'session_123',
    masterSecret: 'secret_key',
    cipherSuite: 'TLS_AES_256_GCM_SHA384',
    tlsVersion: 0x0303
);
$isValid = $validator->validateTLS12Session($session, 'TLS_AES_256_GCM_SHA384', 0x0303);

// 验证 TLS 1.3 PSK 会话
$pskSession = new TLS13PSKSession(/* ... */);
$isPskValid = $validator->validateTLS13PSK($pskSession, 'TLS_AES_128_GCM_SHA256');

// 检查会话是否过期
$isExpired = !$session->isValid();
```

## 高级用法

### 自定义会话存储

```php
<?php

use Tourze\TLSSession\SessionManagerInterface;
use Tourze\TLSSession\SessionInterface;

// 实现自定义会话存储
class DatabaseSessionManager implements SessionManagerInterface
{
    public function createSession(string $cipherSuite, string $masterSecret): SessionInterface
    {
        // 数据库存储的自定义实现
    }
    
    public function storeSession(SessionInterface $session): void
    {
        // 在数据库中存储会话
    }
    
    // ... 其他接口方法
}
```

### 会话验证规则

```php
<?php

use Tourze\TLSSession\SessionSecurityValidator;

$validator = new SessionSecurityValidator();

// 定义服务器安全选项
$serverOptions = [
    'allowDowngrade' => false,
    'requireExactMatch' => true,
    'minimumTlsVersion' => 0x0304, // TLS 1.3
    'allowedCipherSuites' => [
        'TLS_AES_256_GCM_SHA384',
        'TLS_AES_128_GCM_SHA256',
    ],
];

// 根据服务器选项验证会话
$isValid = $validator->validateSessionAgainstServerOptions($session, $serverOptions);
```

### 早期数据管理

```php
<?php

use Tourze\TLSSession\EarlyDataManager;
use Tourze\TLSSession\TLS13PSKSession;

$earlyDataManager = new EarlyDataManager();

// 检查是否允许早期数据
if ($earlyDataManager->isEarlyDataAllowed($pskSession)) {
    $earlyData = $earlyDataManager->processEarlyData($data, $pskSession);
}
```

## 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展
- tourze/tls-common
- tourze/tls-crypto-hash
- tourze/tls-crypto-symmetric
- tourze/tls-handshake-flow
- tourze/tls-x509-core

## API 文档

### SessionInterface

所有会话类型的核心接口：

- `getSessionId()`: 获取会话标识符
- `getCipherSuite()`: 获取加密套件
- `getMasterSecret()`: 获取主密钥
- `getCreationTime()`: 获取创建时间戳
- `isValid()`: 检查会话是否有效

### SessionManagerInterface

会话管理接口：

- `createSession()`: 创建新会话
- `getSessionById()`: 通过ID检索会话
- `storeSession()`: 存储会话
- `removeSession()`: 删除会话
- `cleanExpiredSessions()`: 清理过期会话

### SessionTicketManager

会话票据管理：

- `createTicket()`: 创建加密会话票据
- `decryptTicket()`: 解密和验证票据
- `rotateKeys()`: 轮换加密密钥
- `getTicketLifetime()`: 获取票据生命周期

## 测试

```bash
# 运行所有测试
vendor/bin/phpunit packages/tls-session/tests

# 运行覆盖率测试
vendor/bin/phpunit packages/tls-session/tests --coverage-html coverage
```

## 贡献

欢迎贡献代码！请随时提交Pull Request。

## 许可证

MIT许可证。请查看[LICENSE](LICENSE)文件以获取更多信息。
