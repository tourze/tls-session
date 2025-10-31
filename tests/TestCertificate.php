<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use Tourze\TLSX509Core\Certificate\CertificateInterface;

class TestCertificate implements CertificateInterface
{
    public function getRawData(): string
    {
        return 'test';
    }

    public function getFingerprint(string $algorithm = 'sha256'): string
    {
        return 'hash';
    }

    public function getSubject(): array
    {
        return [];
    }

    public function getIssuer(): array
    {
        return [];
    }

    public function getValidFrom(): int
    {
        return 0;
    }

    public function getValidTo(): int
    {
        return 1;
    }

    public function isValid(): bool
    {
        return true;
    }
}
