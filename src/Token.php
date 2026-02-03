<?php

namespace LAVREEK\Library\JWT;

/**
 * Создание JWT токена.
 *
 * Use alg:
 * + HS256 -> SHA-256
 * + HS384 -> SHA-384
 * + HS512 -> SHA-512
 *
 * @link https://datatracker.ietf.org/doc/html/rfc7518
 */
class Token
{
    /** @var string Кодирование SHA-256. */
    const string ALG_SHA256 = "sha256";

    /** @var string Кодирование SHA-384. */
    const string ALG_SHA384 = "sha384";

    /** @var string Кодирование SHA-512 */
    const string ALG_SHA512 = "sha512";

    /** @var array|string[] Доступные варианты алгоритмов. */
    const array jwaAlgs = [
        'sha256' => 'HS256',
        'sha384' => 'HS384',
        'sha512' => 'HS512',
    ];

    /** @var null|string Алгоритм кодирования. */
    private ?string $alg = null;

    /**
     * Сгенерировать JWT токен.
     * @param string|array $header Заголовки.
     * @param string|array $payload Данные.
     * @param string $signatureKey Ключ подписи.
     * @return string
     * @throws \JsonException
     * @throws \Exception
     */
    public function compose(
        string $signatureKey,
        string|array $header = [],
        string|array $payload = [],
    ): string
    {
        if (is_array($header)) {
            $header = empty($header) ? $this->getHeader() : array_merge($this->getHeader(), $header);
            $header = $this->encode(
                json_encode($header, JSON_THROW_ON_ERROR)
            );
        }

        if (is_array($payload)) {
            $payload = empty($payload) ? $this->getPayload() : array_merge($this->getPayload(), $payload);
            $payload = $this->encode(
                json_encode($payload, JSON_THROW_ON_ERROR)
            );
        }

        return sprintf(
            '%s.%s.%s',
            $header,
            $payload,
            $this->encode(
                hash_hmac(
                    $this->alg,
                    "$header.$payload",
                    $signatureKey
                )
            )
        );
    }

    /**
     * Разложить обратно JWT токен.
     * @param string $token Токен.
     * @param string $signatureKey Ключ подписи.
     * @return array
     * @throws \Exception
     */
    public function decompose(string $token, string $signatureKey): array
    {
        $parts = explode('.', $token);
        if (count($parts) != 3) {
            throw new \Exception("Invalid token.");
        }

        [$header, $payload, $signature] = $parts;
        $headerDecoded = json_decode($this->decode($header), true);
        $payloadDecoded = json_decode($this->decode($payload), true);

        if (!$this->verifyHeader($headerDecoded)) {
            throw new \Exception("Invalid token.");
        }

        if (!$alg = $this->getAlgorithm($headerDecoded['alg'])) {
            throw new \Exception("Invalid algorithm.");
        }

        return [
            'header' => $headerDecoded,
            'payload' => $payloadDecoded,
            'signature' => [
                'valid' => ($signature === $this->encode(hash_hmac($alg, "$header.$payload", $signatureKey)))
            ]
        ];
    }

    /**
     * Закодировать строку с помощью Base64.
     * @param string $input Входящий текст.
     * @return string
     */
    public function encode(string $input): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($input));
    }

    /**
     * Раскодировать строку, закодированную текущим классом.
     * @param string $input Входящий текст.
     * @return string
     */
    public function decode(string $input): string
    {
        return str_replace(['-', '_'], ['+', '/'], base64_decode($input));
    }

    /**
     * Получить алгоритм из заданного по классификации JWA.
     * @param string $jwa JWA алгоритм.
     * @return string|null
     */
    private function getAlgorithm(string $jwa): ?string
    {
        if (in_array($jwa, self::jwaAlgs)) {
            return array_search($jwa, self::jwaAlgs);
        }
        return null;
    }

    /**
     * Получить базовые заголовки.
     * @return array
     * @throws \Exception
     */
    private function getHeader(): array
    {
        if (!$this->verifyAlgorithm()) {
            throw new \Exception("Algorithm not supported.");
        }

        return [
            'typ' => 'JWT',
            'alg' => self::jwaAlgs[$this->alg],
        ];
    }

    /**
     * Получить базовые данные.
     * @return array
     */
    private function getPayload(): array
    {
        return [
            'iat' => time(),
        ];
    }

    /**
     * Установить алгоритм кодирования.
     * @param string $alg Алгоритм кодирования.
     * @return $this
     */
    public function setAlgorithm(string $alg): self
    {
        $this->alg = $alg;
        return $this;
    }

    /**
     * Верифицировать доступный алгоритм.
     * @return bool
     * @throws \Exception
     */
    private function verifyAlgorithm(): bool
    {
        if ($this->alg === null) {
            throw new \Exception("Algorithm not selected.");
        }
        return isset(self::jwaAlgs[$this->alg]);
    }

    /**
     * Верифицировать заголовки токена.
     * @param array $header Данные заголовка токена.
     * @return bool
     */
    private function verifyHeader(array $header): bool
    {
        return isset($header['alg']);
    }
}
