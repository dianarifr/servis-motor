<?php

declare(strict_types=1);

/**
 * Koneksi database (PDO + MySQL/MariaDB), PHP 8.4.
 *
 * Kredensial dibaca dari environment variable (DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASS).
 * Untuk lokal cukup ubah nilai default di bawah; untuk produksi set lewat env server.
 */
final class Database
{
    private static ?self $instance = null;

    // PHP 8.4 asymmetric visibility: bisa dibaca dari luar, hanya bisa diisi dari dalam class.
    public private(set) PDO $pdo;

    private function __construct()
    {
        $env = static fn (string $key, string $default): string => getenv($key) ?: $default;

        $dsn = sprintf(
            'mysql:host=%s;port=%s;dbname=%s;charset=utf8mb4',
            $env('DB_HOST', '127.0.0.1'),
            $env('DB_PORT', '3306'),
            $env('DB_NAME', 'service_motor'),
        );

        try {
            // PHP 8.4: PDO::connect() mengembalikan subclass driver (Pdo\Mysql).
            $this->pdo = PDO::connect($dsn, $env('DB_USER', 'root'), $env('DB_PASS', ''), [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false, // prepared statement asli di sisi server
            ]);
        } catch (PDOException $e) {
            // Detail (host/user) hanya ke log, tidak pernah ke pengguna.
            error_log('DB connection failed: ' . $e->getMessage());
            throw new RuntimeException('Tidak dapat terhubung ke database.');
        }
    }

    public static function instance(): self
    {
        return self::$instance ??= new self();
    }

    private function __clone() {}
}