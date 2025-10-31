<?php

declare(strict_types=1);

namespace Tourze\TLSSession;

/**
 * TLS会话管理器接口
 */
interface SessionManagerInterface
{
    /**
     * 创建新会话
     *
     * @param string $cipherSuite  加密套件
     * @param string $masterSecret 主密钥
     *
     * @return SessionInterface 新会话
     */
    public function createSession(string $cipherSuite, string $masterSecret): SessionInterface;

    /**
     * 通过会话ID获取会话
     *
     * @param string $sessionId 会话ID
     *
     * @return SessionInterface|null 会话对象，不存在则返回null
     */
    public function getSessionById(string $sessionId): ?SessionInterface;

    /**
     * 存储会话
     *
     * @param SessionInterface $session 会话对象
     *
     * @return bool 是否成功
     */
    public function storeSession(SessionInterface $session): bool;

    /**
     * 删除会话
     *
     * @param string $sessionId 会话ID
     *
     * @return bool 是否成功
     */
    public function removeSession(string $sessionId): bool;

    /**
     * 清理过期会话
     *
     * @return int 清理的会话数量
     */
    public function cleanExpiredSessions(): int;
}
