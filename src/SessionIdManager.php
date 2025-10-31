<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

/**
 * 基于会话ID的会话管理器实现
 *
 * 用于TLS 1.2及以下版本的会话恢复机制
 */
class SessionIdManager implements SessionManagerInterface
{
    /** @var array<string, SessionInterface> */
    private array $sessions = [];
    private const SESSION_LIFETIME = 3600; // 默认会话有效期为1小时（秒）

    /**
     * 创建新会话
     *
     * @param string $cipherSuite  加密套件
     * @param string $masterSecret 主密钥
     *
     * @return SessionInterface 新会话
     */
    public function createSession(string $cipherSuite, string $masterSecret): SessionInterface
    {
        $sessionId = random_bytes(32);

        return new ConcreteTLSSession(
            sessionId: $sessionId,
            masterSecret: $masterSecret,
            cipherSuite: $cipherSuite,
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );
    }

    /**
     * 通过会话ID获取会话
     *
     * @param string $sessionId 会话ID
     *
     * @return SessionInterface|null 会话对象，不存在则返回null
     */
    public function getSessionById(string $sessionId): ?SessionInterface
    {
        return $this->getSession($sessionId);
    }

    /**
     * 存储会话
     *
     * @param SessionInterface $session 会话对象
     *
     * @return bool 是否成功
     */
    public function storeSession(SessionInterface $session): bool
    {
        $this->sessions[$session->getSessionId()] = $session;
        $this->cleanupExpiredSessions();

        return true;
    }

    /**
     * 根据会话ID获取会话
     *
     * 如果会话不存在或已过期，则返回null
     */
    public function getSession(string $sessionId): ?SessionInterface
    {
        if (!isset($this->sessions[$sessionId])) {
            return null;
        }

        $session = $this->sessions[$sessionId];

        // 检查会话是否过期
        if ($this->isSessionExpired($session)) {
            $this->removeSession($sessionId);

            return null;
        }

        return $session;
    }

    /**
     * 移除指定的会话
     *
     * @param string $sessionId 会话ID
     *
     * @return bool 是否成功
     */
    public function removeSession(string $sessionId): bool
    {
        if (!isset($this->sessions[$sessionId])) {
            return false;
        }

        unset($this->sessions[$sessionId]);

        return true;
    }

    /**
     * 清理过期会话
     *
     * @return int 清理的会话数量
     */
    public function cleanExpiredSessions(): int
    {
        $count = 0;
        foreach ($this->sessions as $sessionId => $session) {
            if ($this->isSessionExpired($session)) {
                $this->removeSession($sessionId);
                ++$count;
            }
        }

        return $count;
    }

    /**
     * 清除所有会话
     */
    public function clearAllSessions(): void
    {
        $this->sessions = [];
    }

    /**
     * 检查会话是否过期
     */
    private function isSessionExpired(SessionInterface $session): bool
    {
        $expiryTime = $session->getCreationTime() + self::SESSION_LIFETIME;

        return time() > $expiryTime;
    }

    /**
     * 清理所有过期会话
     */
    private function cleanupExpiredSessions(): void
    {
        $this->cleanExpiredSessions();
    }
}
