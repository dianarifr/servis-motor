<?php

declare(strict_types=1);

require_once __DIR__ . '/connection.php';

date_default_timezone_set('Asia/Jakarta');
ini_set('display_errors', '0');
error_reporting(E_ALL);

set_exception_handler(static function (Throwable $e): never {
    error_log((string) $e);
    http_response_code(500);
    exit('DEBUG: ' . htmlspecialchars($e->getMessage()));
});

if (!in_array($_SERVER['REQUEST_METHOD'], ['GET', 'POST'], true)) {
    header('Allow: GET, POST');
    http_response_code(405);
    exit;
}

/* ───────────────────────────── helpers ───────────────────────────── */

/** Daftar jenis kendaraan: satu sumber untuk dropdown, validasi, dan nilai default. */
const JENIS_KENDARAAN = ['Motor', 'Mobil'];

function e(mixed $v): string
{
    return htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function validDate(string $s): ?string
{
    $d = DateTimeImmutable::createFromFormat('!Y-m-d', $s);

    return $d && $d->format('Y-m-d') === $s ? $s : null;
}

function tgl(string $ymd): string
{
    static $bulan = ['Jan', 'Feb', 'Mar', 'Apr', 'Mei', 'Jun', 'Jul', 'Agu', 'Sep', 'Okt', 'Nov', 'Des'];
    [$y, $m, $d] = explode('-', $ymd);

    return sprintf('%d %s %s', $d, $bulan[$m - 1], $y);
}

/** Nomor halaman yang ditampilkan, mis. 1 … 4 5 6 … 20 (null = titik-titik). */
function pageWindow(int $page, int $pages, int $around = 1): array
{
    $show = array_unique([1, ...range(max(1, $page - $around), min($pages, $page + $around)), $pages]);
    sort($show);

    $out = [];
    foreach ($show as $i => $n) {
        if ($i && $n - $show[$i - 1] > 1) {
            $out[] = null;
        }
        $out[] = $n;
    }

    return $out;
}

/* ───────────────────────────── security ───────────────────────────── */

final class Security
{
    public private(set) string $nonce;

    public function __construct()
    {
        $this->nonce = base64_encode(random_bytes(16));

        session_start([
            'cookie_httponly'  => true,
            'cookie_samesite'  => 'Lax',
            'cookie_secure'    => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
            'use_strict_mode'  => true,
            'use_only_cookies' => true,
        ]);

        header_remove('X-Powered-By');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: same-origin');
        header(sprintf(
            "Content-Security-Policy: default-src 'self'; script-src 'nonce-%s' https://cdn.tailwindcss.com; "
            . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
            . "img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            $this->nonce,
        ));
    }

    public function csrfToken(): string
    {
        return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
    }

    public function csrfValid(mixed $token): bool
    {
        return is_string($token) && hash_equals($this->csrfToken(), $token);
    }
}

/* ───────────────────────────── model / repository ───────────────────────────── */

final readonly class Filter
{
    public function __construct(
        public string $q = '',
        public ?string $from = null,
        public ?string $to = null,
    ) {}

    public static function fromQuery(array $get): self
    {
        $str = static fn (string $k): string => is_string($get[$k] ?? null) ? trim($get[$k]) : '';

        $from = validDate($str('from'));
        $to   = validDate($str('to'));
        if ($from && $to && $from > $to) {
            [$from, $to] = [$to, $from];
        }

        return new self(mb_substr($str('q'), 0, 100), $from, $to);
    }

    public function active(): bool
    {
        return $this->q !== '' || $this->from || $this->to;
    }

    public function toArray(): array
    {
        return array_filter(['q' => $this->q, 'from' => $this->from, 'to' => $this->to], static fn ($v) => $v !== '' && $v !== null);
    }
}

final readonly class VehicleRepository
{
    public function __construct(private PDO $db) {}

    public function all(): array
    {
        return $this->db->query('SELECT id, jenis, type, nopol FROM vehicle ORDER BY nopol')->fetchAll();
    }

    public function exists(int $id): bool
    {
        $st = $this->db->prepare('SELECT 1 FROM vehicle WHERE id = ?');
        $st->execute([$id]);

        return (bool) $st->fetchColumn();
    }

    public function create(string $jenis, string $type, string $nopol): int
    {
        $this->db->prepare('INSERT INTO vehicle (jenis, type, nopol) VALUES (?, ?, ?)')
            ->execute([$jenis, $type, $nopol]);

        return (int) $this->db->lastInsertId();
    }
}

final readonly class TransactionRepository
{
    private const FROM = 'FROM `transaction` t JOIN vehicle v ON v.id = t.vehicle_id';

    public function __construct(private PDO $db) {}

    /** @return array{0: string, 1: array<string, string>} */
    private function where(Filter $f): array
    {
        $where = [];
        $params = [];

        if ($f->q !== '') {
            // Native prepared statement tidak boleh memakai nama placeholder yang sama berulang.
            $like = '%' . addcslashes($f->q, '\\%_') . '%';
            $where[] = '(v.nopol LIKE :q1 OR v.type LIKE :q2 OR v.jenis LIKE :q3 OR t.note LIKE :q4)';
            $params += [':q1' => $like, ':q2' => $like, ':q3' => $like, ':q4' => $like];
        }
        if ($f->from) {
            $where[] = 't.`date` >= :from';
            $params[':from'] = $f->from;
        }
        if ($f->to) {
            $where[] = 't.`date` <= :to';
            $params[':to'] = $f->to;
        }

        return [$where ? 'WHERE ' . implode(' AND ', $where) : '', $params];
    }

    public function count(Filter $f): int
    {
        [$where, $params] = $this->where($f);
        $st = $this->db->prepare('SELECT COUNT(*) ' . self::FROM . " $where");
        $st->execute($params);

        return (int) $st->fetchColumn();
    }

    public function search(Filter $f, int $limit, int $offset): array
    {
        [$where, $params] = $this->where($f);
        $st = $this->db->prepare(
            'SELECT t.id, t.vehicle_id, t.`date`, t.spidometer, t.nominal, t.note, v.jenis, v.type, v.nopol '
            . self::FROM . " $where ORDER BY t.`date` DESC, t.id DESC LIMIT :limit OFFSET :offset",
        );
        foreach ($params as $k => $v) {
            $st->bindValue($k, $v);
        }
        $st->bindValue(':limit', $limit, PDO::PARAM_INT);
        $st->bindValue(':offset', $offset, PDO::PARAM_INT);
        $st->execute();

        return $st->fetchAll();
    }

    public function create(int $vehicleId, string $date, int $km, int $nominal, ?string $note): void
    {
        $this->db->prepare('INSERT INTO `transaction` (`date`, vehicle_id, spidometer, nominal, note) VALUES (?, ?, ?, ?, ?)')
            ->execute([$date, $vehicleId, $km, $nominal, $note]);
    }

    public function exists(int $id): bool
    {
        $st = $this->db->prepare('SELECT 1 FROM `transaction` WHERE id = ?');
        $st->execute([$id]);

        return (bool) $st->fetchColumn();
    }

    public function update(int $id, int $vehicleId, string $date, int $km, int $nominal, ?string $note): void
    {
        $this->db->prepare('UPDATE `transaction` SET `date` = ?, vehicle_id = ?, spidometer = ?, nominal = ?, note = ? WHERE id = ?')
            ->execute([$date, $vehicleId, $km, $nominal, $note, $id]);
    }

    public function delete(int $id): void
    {
        $this->db->prepare('DELETE FROM `transaction` WHERE id = ?')->execute([$id]);
    }
}

/* ───────────────────────────── controller ───────────────────────────── */

final class ServiceController
{
    private const PER_PAGE = 15;
    private const FIELDS = ['id', 'vehicle_id', 'jenis', 'type', 'nopol', 'date', 'spidometer', 'nominal', 'note'];

    public function __construct(
        private readonly PDO $db,
        private readonly Security $security,
        private readonly VehicleRepository $vehicles,
        private readonly TransactionRepository $transactions,
    ) {}

    public function handlePost(Filter $filter): never
    {
        if (!$this->security->csrfValid($_POST['csrf'] ?? null)) {
            http_response_code(419);
            exit('Sesi kedaluwarsa. Muat ulang halaman lalu coba lagi.');
        }

        if (($_POST['action'] ?? '') === 'delete') {
            $this->handleDelete();
        } else {
            $this->handleSave();
        }

        $page = filter_var($_GET['page'] ?? 1, FILTER_VALIDATE_INT) ?: 1;
        $qs = http_build_query($filter->toArray() + ($page > 1 ? ['page' => $page] : []));
        header('Location: ' . $_SERVER['SCRIPT_NAME'] . ($qs ? "?$qs" : ''), true, 303);
        exit;
    }

    private function handleSave(): void
    {
        [$data, $errors, $old] = $this->validate($_POST);

        if (!$errors) {
            try {
                $this->save($data);
                $_SESSION['flash'] = ['ok' => $data['id'] ? 'Perubahan disimpan.' : 'Catatan servis disimpan.'];
            } catch (PDOException $e) {
                if (($e->errorInfo[1] ?? 0) === 1062) {
                    $errors['nopol'] = 'Nopol sudah terdaftar. Pilih dari daftar kendaraan.';
                } else {
                    error_log((string) $e);
                    $errors['form'] = 'Catatan gagal disimpan. Coba lagi.';
                }
            }
        }

        if ($errors) {
            $_SESSION['flash'] = ['errors' => $errors, 'old' => $old];
        }
    }

    private function handleDelete(): void
    {
        $id = filter_var($_POST['id'] ?? '', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

        try {
            if ($id !== false && $this->transactions->exists($id)) {
                $this->transactions->delete($id);
                $_SESSION['flash'] = ['ok' => 'Catatan servis dihapus.'];
            } else {
                $_SESSION['flash'] = ['fail' => 'Catatan tidak ditemukan. Mungkin sudah dihapus.'];
            }
        } catch (PDOException $e) {
            error_log((string) $e);
            $_SESSION['flash'] = ['fail' => 'Catatan gagal dihapus. Coba lagi.'];
        }
    }

    public function index(Filter $filter, mixed $pageParam): array
    {
        $total = $this->transactions->count($filter);
        $pages = max(1, (int) ceil($total / self::PER_PAGE));
        $page  = min($pages, max(1, filter_var($pageParam, FILTER_VALIDATE_INT) ?: 1));
        $flash = $_SESSION['flash'] ?? [];
        unset($_SESSION['flash']);

        return [
            'rows'     => $this->transactions->search($filter, self::PER_PAGE, ($page - 1) * self::PER_PAGE),
            'vehicles' => $vehicles = $this->vehicles->all(),
            'total'    => $total,
            'pages'    => $pages,
            'page'     => $page,
            'from'     => $total ? ($page - 1) * self::PER_PAGE + 1 : 0,
            'to'       => min($total, $page * self::PER_PAGE),
            'ok'       => $flash['ok'] ?? null,
            'fail'     => $flash['fail'] ?? null,
            'errors'   => $flash['errors'] ?? [],
            'old'      => ($flash['old'] ?? []) + [
                'id'         => '',
                'vehicle_id' => $vehicles ? '' : 'new',
                'jenis'      => JENIS_KENDARAAN[0],
                'date'       => date('Y-m-d'),
            ],
        ];
    }

    /** @return array{0: array, 1: array<string, string>, 2: array<string, string>} */
    private function validate(array $in): array
    {
        $str = static fn (string $k): string => is_string($in[$k] ?? null) && mb_check_encoding($in[$k], 'UTF-8')
            ? trim($in[$k])
            : '';
        $old = array_combine(self::FIELDS, array_map($str, self::FIELDS));
        $err = [];
        $data = ['id' => null, 'vehicle_id' => null];

        if ($old['id'] !== '') {
            $data['id'] = filter_var($old['id'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
            if ($data['id'] === false || !$this->transactions->exists($data['id'])) {
                $err['form'] = 'Catatan tidak ditemukan. Mungkin sudah dihapus.';
            }
        }

        if ($old['vehicle_id'] === 'new') {
            if (!in_array($old['jenis'], JENIS_KENDARAAN, true)) {
                $err['jenis'] = 'Pilih jenis kendaraan.';
            }
            if ($old['type'] === '' || mb_strlen($old['type']) > 100) {
                $err['type'] = 'Isi tipe kendaraan, maksimal 100 karakter.';
            }
            $nopol = $this->normalizeNopol($old['nopol']);
            if ($nopol === null) {
                $err['nopol'] = 'Format nopol tidak valid, contoh: L 1234 AB.';
            }
            $data += ['jenis' => $old['jenis'], 'type' => $old['type'], 'nopol' => $nopol];
        } else {
            $id = filter_var($old['vehicle_id'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
            if ($id === false || !$this->vehicles->exists($id)) {
                $err['vehicle_id'] = 'Pilih kendaraan dari daftar.';
            }
            $data['vehicle_id'] = $id;
        }

        $date = validDate($old['date']);
        if ($date === null || $date > date('Y-m-d')) {
            $err['date'] = 'Tanggal tidak valid atau melewati hari ini.';
        }

        $km = filter_var($old['spidometer'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 9_999_999]]);
        if ($km === false) {
            $err['spidometer'] = 'Isi spidometer dengan angka 0 sampai 9.999.999 km.';
        }

        $nominal = filter_var($old['nominal'], FILTER_VALIDATE_INT, ['options' => ['min_range' => 0, 'max_range' => 999_999_999]]);
        if ($nominal === false) {
            $err['nominal'] = 'Isi nominal dengan angka 0 sampai 999.999.999.';
        }

        if (mb_strlen($old['note']) > 500) {
            $err['note'] = 'Catatan maksimal 500 karakter.';
        }

        return [$data + ['date' => $date, 'km' => $km, 'nominal' => $nominal, 'note' => $old['note'] ?: null], $err, $old];
    }

    private function normalizeNopol(string $raw): ?string
    {
        $x = strtoupper(preg_replace('/[\s.\-]/', '', $raw));

        return preg_match('/^([A-Z]{1,2})(\d{1,4})([A-Z]{0,3})$/', $x, $m) ? trim("$m[1] $m[2] $m[3]") : null;
    }

    private function save(array $d): void
    {
        $this->db->beginTransaction();
        try {
            $vehicleId = $d['vehicle_id'] ?? $this->vehicles->create($d['jenis'], $d['type'], $d['nopol']);
            $d['id']
                ? $this->transactions->update($d['id'], $vehicleId, $d['date'], $d['km'], $d['nominal'], $d['note'])
                : $this->transactions->create($vehicleId, $d['date'], $d['km'], $d['nominal'], $d['note']);
            $this->db->commit();
        } catch (Throwable $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }
}

/* ───────────────────────────── bootstrap ───────────────────────────── */

$security = new Security();

try {
    $db = Database::instance()->pdo;
} catch (RuntimeException) {
    http_response_code(503);
    exit('Layanan sedang tidak tersedia. Coba lagi beberapa saat.');
}

$app = new ServiceController($db, $security, new VehicleRepository($db), new TransactionRepository($db));
$filter = Filter::fromQuery($_GET);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $app->handlePost($filter);
}

$v = $app->index($filter, $_GET['page'] ?? 1);
['rows' => $rows, 'vehicles' => $vehicles, 'errors' => $errors, 'old' => $old] = $v;
$editing = $old['id'] !== '';

$pageUrl = static fn (int $p): string => '?' . http_build_query($filter->toArray() + ($p > 1 ? ['page' => $p] : []));

$input = 'mt-1 w-full rounded-lg border border-line bg-white px-3 py-2.5 text-base focus:border-ink focus:outline-none focus:ring-2 focus:ring-lamp';
$btnPrimary = 'inline-flex items-center justify-center rounded-lg bg-lamp px-5 py-2.5 font-semibold text-ink hover:bg-[#f3b51c] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink';
$btnGhost = 'inline-flex items-center justify-center rounded-lg border border-line bg-white px-4 py-2.5 font-medium hover:bg-paper focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink';
$fieldError = static fn (string $k): string => isset($errors[$k])
    ? '<p data-err class="mt-1 text-sm text-red-700">' . e($errors[$k]) . '</p>'
    : '';
$odo = static fn (int $km): string => sprintf(
    '<span class="inline-flex items-baseline gap-1 whitespace-nowrap rounded-md border border-lamp/30 bg-dash px-2.5 py-1 font-digit text-xl font-extrabold tabular-nums tracking-wide text-lamp shadow-[0_0_10px_rgba(232,164,0,0.15)]">'
    . '%s<span class="font-sans text-xs font-bold text-lamp/70">km</span>'
    . '</span>',
    number_format($km, 0, ',', '.')
);
$rupiah = static fn (int $n): string => 'Rp' . number_format($n, 0, ',', '.');
$btnEdit = 'rounded-md px-2.5 py-2 text-sm font-medium hover:bg-paper focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink';
$btnDelete = 'rounded-md px-2.5 py-2 text-sm font-medium text-red-700 hover:bg-red-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-red-700';
$btnDanger = 'inline-flex items-center justify-center rounded-lg bg-red-700 px-5 py-2.5 font-semibold text-white hover:bg-red-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-700';
$actions = static fn (array $r): string => sprintf(
    '<div class="flex gap-1">'
    . '<button type="button" data-edit data-id="%d" data-vehicle="%d" data-date="%s" data-km="%d" data-nominal="%d" data-note="%s" class="%s">Ubah</button>'
    . '<button type="button" data-delete data-id="%d" data-label="%s" class="%s">Hapus</button></div>',
    $r['id'], $r['vehicle_id'], e($r['date']), $r['spidometer'], $r['nominal'], e($r['note']), $btnEdit,
    $r['id'], e($r['nopol'] . ', ' . tgl($r['date'])), $btnDelete,
);
?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Catatan Servis Kendaraan</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Archivo:wght@400;500;600;700&family=Big+Shoulders+Display:wght@600;800&display=swap" rel="stylesheet">
    <script nonce="<?= e($security->nonce) ?>" src="https://cdn.tailwindcss.com"></script>
    <script nonce="<?= e($security->nonce) ?>">
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Archivo', 'system-ui', 'sans-serif'],
                        digit: ['"Big Shoulders Display"', 'Impact', 'sans-serif'],
                    },
                    colors: { ink: '#12202B', muted: '#5B6B77', line: '#CBD3D9', paper: '#E9ECEE', lamp: '#E8A400', dash: '#0F1A22' },
                },
            },
        };
    </script>
    <style>body:has(dialog[open]) { overflow: hidden; }</style>
</head>
<body class="min-h-screen bg-paper font-sans text-ink antialiased">
<main class="mx-auto max-w-5xl px-4 py-6 sm:py-10">

    <!-- Bagian 1: judul + tombol tambah -->
    <section class="flex items-end justify-between gap-4">
        <a href="?" class="group block">
            <h1 class="font-digit text-4xl font-extrabold leading-none sm:text-5xl group-hover:opacity-80 transition-opacity">Catatan servis</h1>
            <p class="mt-2 text-sm text-muted">Riwayat servis motor dan mobil</p>
        </a>
        <button type="button" id="btn-add" class="<?= $btnPrimary ?>">Tambah</button>
    </section>

    <?php if ($v['ok']): ?>
        <p role="status" class="mt-5 rounded-lg border-l-4 border-lamp bg-white px-4 py-3 text-sm"><?= e($v['ok']) ?></p>
    <?php endif; ?>
    <?php if ($v['fail']): ?>
        <p role="alert" class="mt-5 rounded-lg border-l-4 border-red-700 bg-white px-4 py-3 text-sm text-red-800"><?= e($v['fail']) ?></p>
    <?php endif; ?>

    <!-- Bagian 2: filter + tabel -->
    <section class="mt-6 overflow-hidden rounded-xl border border-line bg-white">
        <form method="get" class="grid gap-3 border-b border-line p-4 sm:grid-cols-[1fr_auto_auto_auto] sm:items-end">
            <label class="block">
                <span class="text-sm font-medium">Cari</span>
                <input type="search" name="q" value="<?= e($filter->q) ?>" maxlength="100" placeholder="Nopol, tipe, atau catatan" class="<?= $input ?>">
            </label>
            <div class="grid grid-cols-2 gap-3 sm:contents">
                <label class="block">
                    <span class="text-sm font-medium">Dari tanggal</span>
                    <input type="date" name="from" value="<?= e($filter->from) ?>" class="<?= $input ?>">
                </label>
                <label class="block">
                    <span class="text-sm font-medium">Sampai tanggal</span>
                    <input type="date" name="to" value="<?= e($filter->to) ?>" class="<?= $input ?>">
                </label>
            </div>
            <div class="flex gap-2">
                <button type="submit" class="<?= $btnPrimary ?> flex-1 sm:flex-none">Cari</button>
                <?php if ($filter->active()): ?>
                    <a href="?" class="<?= $btnGhost ?>">Reset</a>
                <?php endif; ?>
            </div>
        </form>

        <?php if (!$rows): ?>
            <p class="px-4 py-12 text-center text-muted">
                <?= $filter->active()
                    ? 'Tidak ada catatan yang cocok. Ubah kata kunci atau rentang tanggal.'
                    : 'Belum ada catatan servis. Tekan Tambah untuk mencatat servis pertama.' ?>
            </p>
        <?php else: ?>
            <!-- Mobile: kartu -->
            <ul class="divide-y divide-line md:hidden">
                <?php foreach ($rows as $r): ?>
                    <li class="p-4">
                        <div class="flex items-start justify-between gap-3">
                            <div class="min-w-0">
                                <p class="font-semibold"><?= e($r['nopol']) ?></p>
                                <p class="truncate text-sm text-muted"><?= e($r['type']) ?>, <?= e($r['jenis']) ?></p>
                            </div>
                            <?= $odo((int) $r['spidometer']) ?>
                        </div>
                        <p class="mt-2 text-sm text-muted"><?= e(tgl($r['date'])) ?> · <?= $rupiah((int) $r['nominal']) ?></p>
                        <?php if ($r['note']): ?>
                            <p class="mt-1 whitespace-pre-line break-words text-sm"><?= e($r['note']) ?></p>
                        <?php endif; ?>
                        <div class="-mb-2 mt-2 flex justify-end"><?= $actions($r) ?></div>
                    </li>
                <?php endforeach; ?>
            </ul>

            <!-- Desktop: tabel -->
            <div class="hidden overflow-x-auto md:block">
                <table class="w-full text-left text-sm">
                    <thead class="border-b border-line text-muted">
                    <tr>
                        <th class="px-4 py-3 font-medium">Tanggal</th>
                        <th class="px-4 py-3 font-medium">Nopol</th>
                        <th class="px-4 py-3 font-medium">Kendaraan</th>
                        <th class="px-4 py-3 text-right font-medium">Spidometer</th>
                        <th class="px-4 py-3 text-right font-medium">Biaya</th>
                        <th class="px-4 py-3 font-medium">Catatan</th>
                        <th class="px-4 py-3"><span class="sr-only">Aksi</span></th>
                    </tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                    <?php foreach ($rows as $r): ?>
                        <tr class="align-top">
                            <td class="whitespace-nowrap px-4 py-3"><?= e(tgl($r['date'])) ?></td>
                            <td class="whitespace-nowrap px-4 py-3 font-semibold"><?= e($r['nopol']) ?></td>
                            <td class="px-4 py-3"><?= e($r['jenis']) ?> - <?= e($r['type']) ?></td>
                            <td class="px-4 py-3 text-right"><?= $odo((int) $r['spidometer']) ?></td>
                            <td class="whitespace-nowrap px-4 py-3 text-right"><?= $rupiah((int) $r['nominal']) ?></td>
                            <td class="max-w-xs whitespace-pre-line break-words px-4 py-3"><?= e($r['note']) ?></td>
                            <td class="whitespace-nowrap px-4 py-3 text-right"><?= $actions($r) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <nav class="flex flex-col items-center justify-between gap-3 border-t border-line p-4 text-sm sm:flex-row" aria-label="Halaman">
                <p class="text-muted"><?= $v['from'] ?>–<?= $v['to'] ?> dari <?= $v['total'] ?></p>

                <?php if ($v['pages'] > 1): ?>
                    <?php
                    $pgBtn = 'inline-flex h-10 min-w-10 items-center justify-center rounded-lg px-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ink';
                    ?>
                    <ul class="flex flex-wrap items-center justify-center gap-1">
                        <li>
                            <?php if ($v['page'] > 1): ?>
                                <a href="<?= e($pageUrl($v['page'] - 1)) ?>" aria-label="Halaman sebelumnya" class="<?= $pgBtn ?> border border-line bg-white hover:bg-paper">&lsaquo;</a>
                            <?php else: ?>
                                <span class="<?= $pgBtn ?> border border-line text-muted opacity-40">&lsaquo;</span>
                            <?php endif; ?>
                        </li>

                        <?php foreach (pageWindow($v['page'], $v['pages']) as $n): ?>
                            <li>
                                <?php if ($n === null): ?>
                                    <span class="px-1 text-muted">&hellip;</span>
                                <?php elseif ($n === $v['page']): ?>
                                    <span aria-current="page" class="<?= $pgBtn ?> bg-ink font-semibold text-white"><?= $n ?></span>
                                <?php else: ?>
                                    <a href="<?= e($pageUrl($n)) ?>" aria-label="Halaman <?= $n ?>" class="<?= $pgBtn ?> border border-line bg-white hover:bg-paper"><?= $n ?></a>
                                <?php endif; ?>
                            </li>
                        <?php endforeach; ?>

                        <li>
                            <?php if ($v['page'] < $v['pages']): ?>
                                <a href="<?= e($pageUrl($v['page'] + 1)) ?>" aria-label="Halaman berikutnya" class="<?= $pgBtn ?> border border-line bg-white hover:bg-paper">&rsaquo;</a>
                            <?php else: ?>
                                <span class="<?= $pgBtn ?> border border-line text-muted opacity-40">&rsaquo;</span>
                            <?php endif; ?>
                        </li>
                    </ul>
                <?php endif; ?>
            </nav>
        <?php endif; ?>
    </section>
</main>

<!-- Modal tambah catatan -->
<dialog id="modal" data-today="<?= date('Y-m-d') ?>" <?= $errors ? 'data-open="1"' : '' ?>
        class="m-0 mt-auto w-full max-w-full rounded-t-2xl bg-white p-0 text-ink shadow-xl backdrop:bg-ink/60 sm:m-auto sm:max-w-lg sm:rounded-2xl">
    <form method="post" id="form" class="space-y-4 p-5">
        <input type="hidden" name="csrf" value="<?= e($security->csrfToken()) ?>">
        <input type="hidden" name="action" value="save">
        <input type="hidden" name="id" value="<?= e($old['id']) ?>">

        <div class="flex items-center justify-between">
            <h2 id="modal-title" class="font-digit text-3xl font-extrabold leading-none"><?= $editing ? 'Ubah catatan servis' : 'Tambah catatan servis' ?></h2>
            <button type="button" data-close class="rounded-lg p-2 hover:bg-paper focus-visible:outline focus-visible:outline-2 focus-visible:outline-ink" aria-label="Tutup">
                <svg class="h-5 w-5" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M5 5l10 10M15 5L5 15"/></svg>
            </button>
        </div>

        <?php if (isset($errors['form'])): ?>
            <p role="alert" data-err class="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-800"><?= e($errors['form']) ?></p>
        <?php endif; ?>

        <label class="block">
            <span class="text-sm font-medium">Kendaraan</span>
            <select name="vehicle_id" id="vehicle_id" required autofocus class="<?= $input ?>">
                <option value="" disabled <?= $old['vehicle_id'] === '' ? 'selected' : '' ?>>Pilih kendaraan</option>
                <?php foreach ($vehicles as $veh): ?>
                    <option value="<?= (int) $veh['id'] ?>" <?= (string) $veh['id'] === $old['vehicle_id'] ? 'selected' : '' ?>>
                        <?= e($veh['nopol']) ?> – <?= e($veh['type']) ?>
                    </option>
                <?php endforeach; ?>
                <option value="new" <?= $old['vehicle_id'] === 'new' ? 'selected' : '' ?>>Kendaraan baru…</option>
            </select>
            <?= $fieldError('vehicle_id') ?>
        </label>

        <fieldset id="new-vehicle" class="space-y-4 rounded-lg bg-paper p-3 <?= $old['vehicle_id'] === 'new' ? '' : 'hidden' ?>" <?= $old['vehicle_id'] === 'new' ? '' : 'disabled' ?>>
            <div class="grid grid-cols-2 gap-3">
                <label class="block">
                    <span class="text-sm font-medium">Jenis</span>
                    <select name="jenis" required class="<?= $input ?>">
                        <?php foreach (JENIS_KENDARAAN as $jenis): ?>
                            <option value="<?= e($jenis) ?>" <?= $old['jenis'] === $jenis ? 'selected' : '' ?>><?= e($jenis) ?></option>
                        <?php endforeach; ?>
                    </select>
                    <?= $fieldError('jenis') ?>
                </label>
                <label class="block">
                    <span class="text-sm font-medium">Nopol</span>
                    <input type="text" name="nopol" value="<?= e($old['nopol'] ?? '') ?>" required maxlength="15" autocapitalize="characters" autocomplete="off" placeholder="L 1234 AB" class="<?= $input ?> uppercase">
                    <?= $fieldError('nopol') ?>
                </label>
            </div>
            <label class="block">
                <span class="text-sm font-medium">Tipe</span>
                <input type="text" name="type" value="<?= e($old['type'] ?? '') ?>" required maxlength="100" placeholder="Honda Beat 2021" class="<?= $input ?>">
                <?= $fieldError('type') ?>
            </label>
        </fieldset>

        <div class="grid grid-cols-2 gap-3">
            <label class="block">
                <span class="text-sm font-medium">Tanggal servis</span>
                <input type="date" name="date" value="<?= e($old['date']) ?>" max="<?= date('Y-m-d') ?>" required class="<?= $input ?>">
                <?= $fieldError('date') ?>
            </label>
            <label class="block">
                <span class="text-sm font-medium">Spidometer (km)</span>
                <input type="number" name="spidometer" value="<?= e($old['spidometer'] ?? '') ?>" min="0" max="9999999" step="1" inputmode="numeric" required placeholder="24500" class="<?= $input ?>">
                <?= $fieldError('spidometer') ?>
            </label>
        </div>

        <label class="block">
            <span class="text-sm font-medium">Nominal (Rp)</span>
            <input type="number" name="nominal" value="<?= e($old['nominal'] ?? '') ?>" min="0" max="999999999" step="1" inputmode="numeric" required placeholder="150000" class="<?= $input ?>">
            <?= $fieldError('nominal') ?>
        </label>

        <label class="block">
            <span class="text-sm font-medium">Catatan</span>
            <textarea name="note" rows="3" maxlength="500" placeholder="Ganti oli, kampas rem depan…" class="<?= $input ?>"><?= e($old['note'] ?? '') ?></textarea>
            <?= $fieldError('note') ?>
        </label>

        <div class="flex justify-end gap-2 pt-1">
            <button type="button" data-close class="<?= $btnGhost ?>">Batal</button>
            <button type="submit" id="modal-submit" class="<?= $btnPrimary ?>"><?= $editing ? 'Simpan perubahan' : 'Simpan catatan' ?></button>
        </div>
    </form>
</dialog>

<!-- Konfirmasi hapus -->
<dialog id="confirm"
        class="m-0 mt-auto w-full max-w-full rounded-t-2xl bg-white p-0 text-ink shadow-xl backdrop:bg-ink/60 sm:m-auto sm:max-w-md sm:rounded-2xl">
    <form method="post" class="space-y-4 p-5">
        <input type="hidden" name="csrf" value="<?= e($security->csrfToken()) ?>">
        <input type="hidden" name="action" value="delete">
        <input type="hidden" name="id" id="del-id" value="">
        <h2 class="font-digit text-3xl font-extrabold leading-none">Hapus catatan servis?</h2>
        <p class="text-sm text-muted">Catatan <strong id="del-label" class="font-semibold text-ink"></strong> akan dihapus permanen. Data kendaraan tetap tersimpan.</p>
        <div class="flex justify-end gap-2">
            <button type="button" data-close class="<?= $btnGhost ?>">Batal</button>
            <button type="submit" class="<?= $btnDanger ?>">Hapus catatan</button>
        </div>
    </form>
</dialog>

<script nonce="<?= e($security->nonce) ?>">
    const dlg = document.getElementById('modal');
    const confirmDlg = document.getElementById('confirm');
    const form = document.getElementById('form');
    const sel = form.elements['vehicle_id'];
    const box = document.getElementById('new-vehicle');
    const hasVehicles = sel.options.length > 2; // placeholder + "Kendaraan baru" + daftar kendaraan

    const sync = () => {
        const isNew = sel.value === 'new';
        box.classList.toggle('hidden', !isNew);
        box.disabled = !isNew; // field yang disabled tidak divalidasi dan tidak dikirim
    };
    sel.addEventListener('change', sync);
    sync();

    // Satu modal untuk tambah dan ubah: tanpa data = tambah, dengan data = ubah.
    const openForm = (d = {}) => {
        dlg.querySelectorAll('[data-err]').forEach((n) => n.remove());
        const editing = Boolean(d.id);
        form.elements['id'].value = d.id ?? '';
        sel.value = d.vehicle ?? (hasVehicles ? '' : 'new');
        form.elements['jenis'].selectedIndex = 0;
        form.elements['type'].value = '';
        form.elements['nopol'].value = '';
        form.elements['date'].value = d.date ?? dlg.dataset.today;
        form.elements['spidometer'].value = d.km ?? '';
        form.elements['nominal'].value = d.nominal ?? '';
        form.elements['note'].value = d.note ?? '';
        document.getElementById('modal-title').textContent = editing ? 'Ubah catatan servis' : 'Tambah catatan servis';
        document.getElementById('modal-submit').textContent = editing ? 'Simpan perubahan' : 'Simpan catatan';
        sync();
        dlg.showModal();
    };

    document.getElementById('btn-add').addEventListener('click', () => openForm());
    document.querySelectorAll('[data-edit]').forEach((b) => b.addEventListener('click', () => openForm(b.dataset)));
    document.querySelectorAll('[data-delete]').forEach((b) => b.addEventListener('click', () => {
        document.getElementById('del-id').value = b.dataset.id;
        document.getElementById('del-label').textContent = b.dataset.label;
        confirmDlg.showModal();
    }));

    document.querySelectorAll('dialog').forEach((d) => {
        d.querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => d.close()));
        d.addEventListener('click', (ev) => { if (ev.target === d) d.close(); });
    });

    if (dlg.dataset.open) dlg.showModal(); // ada error validasi: buka lagi dengan isian sebelumnya
</script>
</body>
</html>