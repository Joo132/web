<?php
/**
 * Database Connection Class
 *
 * Handles MySQL database connections using PDO with prepared statements
 * for secure database operations.
 */

// Prevent direct access
if (!defined('LICENSE_SERVER')) {
    http_response_code(403);
    exit('Direct access not allowed');
}

class Database
{
    private static ?PDO $instance = null;
    private static int $queryCount = 0;

    /**
     * Get database connection instance (singleton pattern)
     */
    public static function getInstance(): PDO
    {
        if (self::$instance === null) {
            self::connect();
        }
        return self::$instance;
    }

    /**
     * Establish database connection
     */
    private static function connect(): void
    {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            DB_HOST,
            DB_PORT,
            DB_NAME,
            DB_CHARSET
        );

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_STRINGIFY_FETCHES => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci"
        ];

        try {
            self::$instance = new PDO($dsn, DB_USER, DB_PASS, $options);
        } catch (PDOException $e) {
            if (APP_DEBUG) {
                throw new Exception('Database connection failed: ' . $e->getMessage());
            }
            throw new Exception('Database connection failed');
        }
    }

    /**
     * Execute a query and return results
     */
    public static function query(string $sql, array $params = []): array
    {
        $pdo = self::getInstance();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        self::$queryCount++;
        return $stmt->fetchAll();
    }

    /**
     * Execute a query and return single row
     */
    public static function queryOne(string $sql, array $params = []): ?array
    {
        $pdo = self::getInstance();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        self::$queryCount++;
        $result = $stmt->fetch();
        return $result ?: null;
    }

    /**
     * Execute a query without returning results (INSERT, UPDATE, DELETE)
     */
    public static function execute(string $sql, array $params = []): int
    {
        $pdo = self::getInstance();
        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        self::$queryCount++;
        return $stmt->rowCount();
    }

    /**
     * Get last inserted ID
     */
    public static function lastInsertId(): string
    {
        return self::getInstance()->lastInsertId();
    }

    /**
     * Begin transaction
     */
    public static function beginTransaction(): bool
    {
        return self::getInstance()->beginTransaction();
    }

    /**
     * Commit transaction
     */
    public static function commit(): bool
    {
        return self::getInstance()->commit();
    }

    /**
     * Rollback transaction
     */
    public static function rollback(): bool
    {
        return self::getInstance()->rollBack();
    }

    /**
     * Check if table exists
     */
    public static function tableExists(string $table): bool
    {
        $sql = "SHOW TABLES LIKE ?";
        $result = self::queryOne($sql, [$table]);
        return $result !== null;
    }

    /**
     * Get query count for debugging
     */
    public static function getQueryCount(): int
    {
        return self::$queryCount;
    }

    /**
     * Close connection
     */
    public static function close(): void
    {
        self::$instance = null;
    }
}

/**
 * Simple Query Builder for common operations
 */
class QueryBuilder
{
    private string $table;
    private array $where = [];
    private array $params = [];
    private array $orderBy = [];
    private ?int $limit = null;
    private ?int $offset = null;

    public function __construct(string $table)
    {
        $this->table = $table;
    }

    public static function table(string $table): self
    {
        return new self($table);
    }

    public function where(string $column, string $operator, $value): self
    {
        $this->where[] = "`$column` $operator ?";
        $this->params[] = $value;
        return $this;
    }

    public function whereEquals(string $column, $value): self
    {
        return $this->where($column, '=', $value);
    }

    public function whereIn(string $column, array $values): self
    {
        $placeholders = implode(',', array_fill(0, count($values), '?'));
        $this->where[] = "`$column` IN ($placeholders)";
        $this->params = array_merge($this->params, $values);
        return $this;
    }

    public function orderBy(string $column, string $direction = 'ASC'): self
    {
        $direction = strtoupper($direction) === 'DESC' ? 'DESC' : 'ASC';
        $this->orderBy[] = "`$column` $direction";
        return $this;
    }

    public function limit(int $limit): self
    {
        $this->limit = $limit;
        return $this;
    }

    public function offset(int $offset): self
    {
        $this->offset = $offset;
        return $this;
    }

    public function get(): array
    {
        $sql = "SELECT * FROM `{$this->table}`";

        if (!empty($this->where)) {
            $sql .= ' WHERE ' . implode(' AND ', $this->where);
        }

        if (!empty($this->orderBy)) {
            $sql .= ' ORDER BY ' . implode(', ', $this->orderBy);
        }

        if ($this->limit !== null) {
            $sql .= ' LIMIT ' . $this->limit;
            if ($this->offset !== null) {
                $sql .= ' OFFSET ' . $this->offset;
            }
        }

        return Database::query($sql, $this->params);
    }

    public function first(): ?array
    {
        $this->limit = 1;
        $results = $this->get();
        return $results[0] ?? null;
    }

    public function count(): int
    {
        $sql = "SELECT COUNT(*) as count FROM `{$this->table}`";

        if (!empty($this->where)) {
            $sql .= ' WHERE ' . implode(' AND ', $this->where);
        }

        $result = Database::queryOne($sql, $this->params);
        return (int)($result['count'] ?? 0);
    }

    public function insert(array $data): string
    {
        $columns = array_keys($data);
        $placeholders = array_fill(0, count($columns), '?');

        $sql = sprintf(
            "INSERT INTO `%s` (`%s`) VALUES (%s)",
            $this->table,
            implode('`, `', $columns),
            implode(', ', $placeholders)
        );

        Database::execute($sql, array_values($data));
        return Database::lastInsertId();
    }

    public function update(array $data): int
    {
        $set = [];
        $params = [];

        foreach ($data as $column => $value) {
            $set[] = "`$column` = ?";
            $params[] = $value;
        }

        $sql = sprintf(
            "UPDATE `%s` SET %s",
            $this->table,
            implode(', ', $set)
        );

        if (!empty($this->where)) {
            $sql .= ' WHERE ' . implode(' AND ', $this->where);
            $params = array_merge($params, $this->params);
        }

        return Database::execute($sql, $params);
    }

    public function delete(): int
    {
        $sql = "DELETE FROM `{$this->table}`";

        if (!empty($this->where)) {
            $sql .= ' WHERE ' . implode(' AND ', $this->where);
        }

        return Database::execute($sql, $this->params);
    }
}
