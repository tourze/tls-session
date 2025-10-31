<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

/**
 * TLS内存会话管理器抽象基类
 *
 * 将会话存储在内存中，仅适用于单进程服务器
 */
abstract class InMemorySessionManager implements SessionManagerInterface
{
    /**
     * 会话存储
     *
     * @var array<string, SessionInterface>
     */
    private array $sessions = [];

    public function createSession(string $cipherSuite, string $masterSecret): SessionInterface
    {
        $session = new ConcreteTLSSession(
            sessionId: bin2hex(random_bytes(16)), // 生成32个字符的随机会话ID
            masterSecret: $masterSecret,
            cipherSuite: $cipherSuite,
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        $this->storeSession($session);

        return $session;
    }

    public function getSessionById(string $sessionId): ?SessionInterface
    {
        if (!isset($this->sessions[$sessionId])) {
            return null;
        }

        $session = $this->sessions[$sessionId];

        // 检查会话是否有效
        if (!$session->isValid()) {
            $this->removeSession($sessionId);

            return null;
        }

        return $session;
    }

    public function storeSession(SessionInterface $session): bool
    {
        $this->sessions[$session->getSessionId()] = $session;

        return true;
    }

    public function removeSession(string $sessionId): bool
    {
        if (isset($this->sessions[$sessionId])) {
            unset($this->sessions[$sessionId]);

            return true;
        }

        return false;
    }

    public function cleanExpiredSessions(): int
    {
        $count = 0;
        $currentTime = time();

        foreach ($this->sessions as $sessionId => $session) {
            if (!$session->isValid($currentTime)) {
                unset($this->sessions[$sessionId]);
                ++$count;
            }
        }

        return $count;
    }
}
