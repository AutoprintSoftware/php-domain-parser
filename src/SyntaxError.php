<?php

declare(strict_types=1);

namespace Pdp;

use InvalidArgumentException;

class SyntaxError extends InvalidArgumentException implements CannotProcessHost
{
    private ?IdnaResult $idnaResult;

    public function fetchIdnaResult(): ?IdnaResult
    {
        return $this->idnaResult;
    }

    public static function dueToInvalidCharacters(string $domain): self
    {
        return new self('The host `'.$domain.'` is invalid: it contains invalid characters.');
    }

    public static function dueToInvalidLength(string $domain): self
    {
        return new self('The host `'.$domain.'` is invalid: its length is longer than 255 bytes in its storage form.');
    }

    public static function dueToIDNAError(string $domain, IdnaResult $result): self
    {
        $exception = new self('The host `'.$domain.'` is invalid for IDN conversion.');
        $exception->idnaResult = $result;

        return $exception;
    }

    public static function dueToInvalidSuffix(Host $publicSuffix, string $type = ''): self
    {
        if ('' === $type) {
            return new self('The suffix `"'.$publicSuffix->value() ?? 'NULL'.'"` is invalid.');
        }

        return new self('The suffix `"'.$publicSuffix->value() ?? 'NULL'.'"` is an invalid `'.$type.'` suffix.');
    }

    public static function dueToUnsupportedType(string $domain): self
    {
        return new self('The domain `'.$domain.'` is invalid: this is an IPv4 host.');
    }

    public static function dueToInvalidLabelKey(Host $domain, int $key): self
    {
        return new self('the given key `'.$key.'` is invalid for the domain `'.($domain->value() ?? 'NULL').'`.');
    }
}
