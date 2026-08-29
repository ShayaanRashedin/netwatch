#include "netwatch/storage/SQLiteEventRepository.hpp"

#include <sqlite3.h>

#include <chrono>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace netwatch {

namespace {

[[noreturn]]
void throwDatabaseError(
    sqlite3* database,
    const std::string_view operation)
{
    throw std::runtime_error {
        std::string {operation}
        + ": "
        + (database == nullptr
            ? "unknown SQLite error"
            : sqlite3_errmsg(database))
    };
}

void execute(sqlite3* database, const char* sql)
{
    char* errorMessage = nullptr;

    const int result = sqlite3_exec(
        database,
        sql,
        nullptr,
        nullptr,
        &errorMessage
    );

    if (result == SQLITE_OK) {
        return;
    }

    const std::string message = errorMessage == nullptr
        ? sqlite3_errmsg(database)
        : errorMessage;

    sqlite3_free(errorMessage);
    throw std::runtime_error {"SQLite execute: " + message};
}

class Statement {
public:
    Statement(sqlite3* database, const char* sql)
        : database_ {database}
    {
        if (sqlite3_prepare_v2(
                database_,
                sql,
                -1,
                &statement_,
                nullptr
            ) != SQLITE_OK) {
            throwDatabaseError(database_, "SQLite prepare");
        }
    }

    ~Statement()
    {
        sqlite3_finalize(statement_);
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    [[nodiscard]]
    sqlite3_stmt* get() const
    {
        return statement_;
    }

private:
    sqlite3* database_ {};
    sqlite3_stmt* statement_ {};
};

void requireBind(
    sqlite3* database,
    const int result)
{
    if (result != SQLITE_OK) {
        throwDatabaseError(database, "SQLite bind");
    }
}

void bindText(
    sqlite3* database,
    sqlite3_stmt* statement,
    const int index,
    const std::string_view value)
{
    if (value.size()
        > static_cast<std::size_t>(
            std::numeric_limits<int>::max())) {
        throw std::length_error {"SQLite text value is too large"};
    }

    requireBind(
        database,
        sqlite3_bind_text(
            statement,
            index,
            value.data(),
            static_cast<int>(value.size()),
            SQLITE_TRANSIENT
        )
    );
}

template <typename T>
void bindOptionalInteger(
    sqlite3* database,
    sqlite3_stmt* statement,
    const int index,
    const std::optional<T>& value)
{
    if (!value.has_value()) {
        requireBind(
            database,
            sqlite3_bind_null(statement, index)
        );
        return;
    }

    requireBind(
        database,
        sqlite3_bind_int64(
            statement,
            index,
            static_cast<sqlite3_int64>(*value)
        )
    );
}

std::string columnText(
    sqlite3_stmt* statement,
    const int column)
{
    const auto* text = sqlite3_column_text(statement, column);

    if (text == nullptr) {
        return {};
    }

    return reinterpret_cast<const char*>(text);
}

std::string_view eventTypeToText(const SocketEventType type)
{
    switch (type) {
    case SocketEventType::Opened:
        return "OPENED";
    case SocketEventType::Closed:
        return "CLOSED";
    case SocketEventType::StateChanged:
        return "STATE_CHANGED";
    }

    return "UNKNOWN";
}

SocketEventType eventTypeFromText(const std::string_view value)
{
    if (value == "OPENED") {
        return SocketEventType::Opened;
    }
    if (value == "CLOSED") {
        return SocketEventType::Closed;
    }
    if (value == "STATE_CHANGED") {
        return SocketEventType::StateChanged;
    }

    throw std::runtime_error {
        "Unknown socket event type in database: "
        + std::string {value}
    };
}

std::string_view familyToText(const IpFamily family)
{
    return family == IpFamily::IPv4 ? "IPv4" : "IPv6";
}

IpFamily familyFromText(const std::string_view value)
{
    if (value == "IPv4") {
        return IpFamily::IPv4;
    }
    if (value == "IPv6") {
        return IpFamily::IPv6;
    }

    throw std::runtime_error {
        "Unknown IP family in database: " + std::string {value}
    };
}

std::string_view protocolToText(const TransportProtocol protocol)
{
    return protocol == TransportProtocol::Tcp ? "TCP" : "UDP";
}

TransportProtocol protocolFromText(const std::string_view value)
{
    if (value == "TCP") {
        return TransportProtocol::Tcp;
    }
    if (value == "UDP") {
        return TransportProtocol::Udp;
    }

    throw std::runtime_error {
        "Unknown transport protocol in database: "
        + std::string {value}
    };
}

std::string_view stateToText(const SocketState state)
{
    switch (state) {
    case SocketState::Established:
        return "ESTABLISHED";
    case SocketState::SynSent:
        return "SYN_SENT";
    case SocketState::SynReceived:
        return "SYN_RECV";
    case SocketState::FinWait1:
        return "FIN_WAIT1";
    case SocketState::FinWait2:
        return "FIN_WAIT2";
    case SocketState::TimeWait:
        return "TIME_WAIT";
    case SocketState::Closed:
        return "CLOSED";
    case SocketState::CloseWait:
        return "CLOSE_WAIT";
    case SocketState::LastAck:
        return "LAST_ACK";
    case SocketState::Listen:
        return "LISTEN";
    case SocketState::Closing:
        return "CLOSING";
    case SocketState::NewSynReceived:
        return "NEW_SYN_RECV";
    case SocketState::Unconnected:
        return "UNCONN";
    case SocketState::Unknown:
        return "UNKNOWN";
    }

    return "UNKNOWN";
}

SocketState stateFromText(const std::string_view value)
{
    if (value == "ESTABLISHED") return SocketState::Established;
    if (value == "SYN_SENT") return SocketState::SynSent;
    if (value == "SYN_RECV") return SocketState::SynReceived;
    if (value == "FIN_WAIT1") return SocketState::FinWait1;
    if (value == "FIN_WAIT2") return SocketState::FinWait2;
    if (value == "TIME_WAIT") return SocketState::TimeWait;
    if (value == "CLOSED") return SocketState::Closed;
    if (value == "CLOSE_WAIT") return SocketState::CloseWait;
    if (value == "LAST_ACK") return SocketState::LastAck;
    if (value == "LISTEN") return SocketState::Listen;
    if (value == "CLOSING") return SocketState::Closing;
    if (value == "NEW_SYN_RECV") return SocketState::NewSynReceived;
    if (value == "UNCONN") return SocketState::Unconnected;
    if (value == "UNKNOWN") return SocketState::Unknown;

    throw std::runtime_error {
        "Unknown socket state in database: " + std::string {value}
    };
}

std::int64_t toEpochMilliseconds(
    const std::chrono::system_clock::time_point timePoint)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        timePoint.time_since_epoch()
    ).count();
}

std::chrono::system_clock::time_point fromEpochMilliseconds(
    const sqlite3_int64 milliseconds)
{
    return std::chrono::system_clock::time_point {
        std::chrono::milliseconds {milliseconds}
    };
}

std::size_t readCount(sqlite3* database, const char* sql)
{
    Statement statement {database, sql};

    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throwDatabaseError(database, "SQLite count");
    }

    return static_cast<std::size_t>(
        sqlite3_column_int64(statement.get(), 0)
    );
}

} // namespace

SQLiteEventRepository::SQLiteEventRepository(
    const std::filesystem::path& databasePath)
{
    const std::string path = databasePath.string();

    const int result = sqlite3_open_v2(
        path.c_str(),
        &database_,
        SQLITE_OPEN_READWRITE
            | SQLITE_OPEN_CREATE
            | SQLITE_OPEN_FULLMUTEX,
        nullptr
    );

    if (result != SQLITE_OK) {
        const std::string message = database_ == nullptr
            ? "unknown SQLite error"
            : sqlite3_errmsg(database_);

        if (database_ != nullptr) {
            sqlite3_close_v2(database_);
            database_ = nullptr;
        }

        throw std::runtime_error {
            "Unable to open SQLite database '"
            + path
            + "': "
            + message
        };
    }

    try {
        if (sqlite3_busy_timeout(database_, 5000) != SQLITE_OK) {
            throwDatabaseError(database_, "SQLite busy timeout");
        }

        initializeSchema();
    } catch (...) {
        sqlite3_close_v2(database_);
        database_ = nullptr;
        throw;
    }
}

SQLiteEventRepository::~SQLiteEventRepository()
{
    if (database_ != nullptr) {
        sqlite3_close_v2(database_);
    }
}

void SQLiteEventRepository::initializeSchema()
{
    execute(database_, "PRAGMA foreign_keys = ON;");
    execute(database_, "PRAGMA journal_mode = WAL;");
    execute(database_, "PRAGMA synchronous = NORMAL;");

    execute(database_, R"sql(
        CREATE TABLE IF NOT EXISTS socket_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observed_at_ms INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            family TEXT NOT NULL,
            protocol TEXT NOT NULL,
            local_address TEXT NOT NULL,
            local_port INTEGER NOT NULL,
            remote_address TEXT NOT NULL,
            remote_port INTEGER NOT NULL,
            state TEXT NOT NULL,
            previous_state TEXT,
            inode INTEGER NOT NULL,
            tx_queue_bytes INTEGER NOT NULL,
            rx_queue_bytes INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS event_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            pid INTEGER NOT NULL,
            start_time_ticks INTEGER,
            uid INTEGER,
            username TEXT NOT NULL,
            name TEXT NOT NULL,
            executable TEXT NOT NULL,
            command_line TEXT NOT NULL,
            FOREIGN KEY(event_id)
                REFERENCES socket_events(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            detected_at_ms INTEGER NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            reason TEXT NOT NULL,
            risk_score INTEGER NOT NULL
                CHECK(risk_score BETWEEN 0 AND 100),
            severity TEXT NOT NULL,
            FOREIGN KEY(event_id)
                REFERENCES socket_events(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS alert_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            detail TEXT NOT NULL,
            FOREIGN KEY(alert_id)
                REFERENCES alerts(id)
                ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_socket_events_observed_at
            ON socket_events(observed_at_ms DESC);

        CREATE INDEX IF NOT EXISTS idx_socket_events_inode
            ON socket_events(inode);

        CREATE INDEX IF NOT EXISTS idx_event_processes_event_id
            ON event_processes(event_id);

        CREATE INDEX IF NOT EXISTS idx_alerts_detected_at
            ON alerts(detected_at_ms DESC);

        CREATE INDEX IF NOT EXISTS idx_alerts_risk_score
            ON alerts(risk_score DESC);

        CREATE INDEX IF NOT EXISTS idx_alerts_rule_id
            ON alerts(rule_id);

        CREATE INDEX IF NOT EXISTS idx_alert_evidence_alert_id
            ON alert_evidence(alert_id, position);

        PRAGMA user_version = 2;
    )sql");
}

void SQLiteEventRepository::persist(
    const SocketEvent& event,
    const std::vector<Alert>& alerts)
{
    static constexpr const char* insertEvent = R"sql(
        INSERT INTO socket_events (
            observed_at_ms,
            event_type,
            family,
            protocol,
            local_address,
            local_port,
            remote_address,
            remote_port,
            state,
            previous_state,
            inode,
            tx_queue_bytes,
            rx_queue_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )sql";

    static constexpr const char* insertProcess = R"sql(
        INSERT INTO event_processes (
            event_id,
            pid,
            start_time_ticks,
            uid,
            username,
            name,
            executable,
            command_line
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
    )sql";

    static constexpr const char* insertAlert = R"sql(
        INSERT INTO alerts (
            event_id,
            detected_at_ms,
            rule_id,
            title,
            reason,
            risk_score,
            severity
        ) VALUES (?, ?, ?, ?, ?, ?, ?);
    )sql";

    static constexpr const char* insertEvidence = R"sql(
        INSERT INTO alert_evidence (
            alert_id,
            position,
            detail
        ) VALUES (?, ?, ?);
    )sql";

    execute(database_, "BEGIN IMMEDIATE TRANSACTION;");

    try {
        Statement eventStatement {database_, insertEvent};
        sqlite3_stmt* eventHandle = eventStatement.get();
        const auto& socket = event.observation.socket;

        requireBind(database_, sqlite3_bind_int64(
            eventHandle, 1, toEpochMilliseconds(event.observed_at)));
        bindText(database_, eventHandle, 2, eventTypeToText(event.type));
        bindText(database_, eventHandle, 3, familyToText(socket.family));
        bindText(database_, eventHandle, 4, protocolToText(socket.protocol));
        bindText(database_, eventHandle, 5, socket.local.address);
        requireBind(database_, sqlite3_bind_int(
            eventHandle, 6, static_cast<int>(socket.local.port)));
        bindText(database_, eventHandle, 7, socket.remote.address);
        requireBind(database_, sqlite3_bind_int(
            eventHandle, 8, static_cast<int>(socket.remote.port)));
        bindText(database_, eventHandle, 9, stateToText(socket.state));

        if (event.previous_state.has_value()) {
            bindText(
                database_,
                eventHandle,
                10,
                stateToText(*event.previous_state)
            );
        } else {
            requireBind(
                database_,
                sqlite3_bind_null(eventHandle, 10)
            );
        }

        requireBind(database_, sqlite3_bind_int64(
            eventHandle,
            11,
            static_cast<sqlite3_int64>(socket.inode)));
        requireBind(database_, sqlite3_bind_int64(
            eventHandle,
            12,
            static_cast<sqlite3_int64>(socket.tx_queue_bytes)));
        requireBind(database_, sqlite3_bind_int64(
            eventHandle,
            13,
            static_cast<sqlite3_int64>(socket.rx_queue_bytes)));

        if (sqlite3_step(eventHandle) != SQLITE_DONE) {
            throwDatabaseError(database_, "SQLite insert event");
        }

        const sqlite3_int64 eventId =
            sqlite3_last_insert_rowid(database_);

        Statement processStatement {database_, insertProcess};

        for (const auto& process : event.observation.owners) {
            sqlite3_stmt* processHandle = processStatement.get();

            requireBind(database_, sqlite3_bind_int64(
                processHandle, 1, eventId));
            requireBind(database_, sqlite3_bind_int(
                processHandle, 2, process.pid));
            bindOptionalInteger(
                database_,
                processHandle,
                3,
                process.start_time_ticks
            );
            bindOptionalInteger(
                database_,
                processHandle,
                4,
                process.uid
            );
            bindText(database_, processHandle, 5, process.username);
            bindText(database_, processHandle, 6, process.name);
            bindText(database_, processHandle, 7, process.executable);
            bindText(database_, processHandle, 8, process.command_line);

            if (sqlite3_step(processHandle) != SQLITE_DONE) {
                throwDatabaseError(database_, "SQLite insert process");
            }

            if (sqlite3_reset(processHandle) != SQLITE_OK) {
                throwDatabaseError(database_, "SQLite reset process insert");
            }

            if (sqlite3_clear_bindings(processHandle) != SQLITE_OK) {
                throwDatabaseError(database_, "SQLite clear process bindings");
            }
        }

        Statement alertStatement {database_, insertAlert};
        Statement evidenceStatement {database_, insertEvidence};

        for (const auto& alert : alerts) {
            if (alert.risk_score < 0 || alert.risk_score > 100) {
                throw std::invalid_argument {
                    "alert risk score must be between 0 and 100"
                };
            }

            sqlite3_stmt* alertHandle = alertStatement.get();

            requireBind(database_, sqlite3_bind_int64(
                alertHandle, 1, eventId));
            requireBind(database_, sqlite3_bind_int64(
                alertHandle,
                2,
                toEpochMilliseconds(alert.detected_at)
            ));
            bindText(database_, alertHandle, 3, alert.rule_id);
            bindText(database_, alertHandle, 4, alert.title);
            bindText(database_, alertHandle, 5, alert.reason);
            requireBind(database_, sqlite3_bind_int(
                alertHandle, 6, alert.risk_score));
            bindText(
                database_,
                alertHandle,
                7,
                alertSeverityToString(alert.severity)
            );

            if (sqlite3_step(alertHandle) != SQLITE_DONE) {
                throwDatabaseError(database_, "SQLite insert alert");
            }

            const sqlite3_int64 alertId =
                sqlite3_last_insert_rowid(database_);

            if (sqlite3_reset(alertHandle) != SQLITE_OK) {
                throwDatabaseError(database_, "SQLite reset alert insert");
            }

            if (sqlite3_clear_bindings(alertHandle) != SQLITE_OK) {
                throwDatabaseError(database_, "SQLite clear alert bindings");
            }

            std::size_t evidencePosition {};

            for (const auto& detail : alert.evidence) {
                sqlite3_stmt* evidenceHandle = evidenceStatement.get();

                requireBind(database_, sqlite3_bind_int64(
                    evidenceHandle, 1, alertId));
                requireBind(database_, sqlite3_bind_int64(
                    evidenceHandle,
                    2,
                    static_cast<sqlite3_int64>(evidencePosition)
                ));
                bindText(database_, evidenceHandle, 3, detail);

                if (sqlite3_step(evidenceHandle) != SQLITE_DONE) {
                    throwDatabaseError(
                        database_,
                        "SQLite insert alert evidence"
                    );
                }

                if (sqlite3_reset(evidenceHandle) != SQLITE_OK) {
                    throwDatabaseError(
                        database_,
                        "SQLite reset evidence insert"
                    );
                }

                if (sqlite3_clear_bindings(evidenceHandle)
                    != SQLITE_OK) {
                    throwDatabaseError(
                        database_,
                        "SQLite clear evidence bindings"
                    );
                }

                ++evidencePosition;
            }
        }

        execute(database_, "COMMIT;");
    } catch (...) {
        try {
            execute(database_, "ROLLBACK;");
        } catch (...) {
        }
        throw;
    }
}

std::vector<StoredSocketEvent>
SQLiteEventRepository::recentEvents(const std::size_t limit) const
{
    if (limit == 0U) {
        return {};
    }

    if (limit > static_cast<std::size_t>(
            std::numeric_limits<sqlite3_int64>::max())) {
        throw std::length_error {"SQLite query limit is too large"};
    }

    static constexpr const char* selectEvents = R"sql(
        SELECT
            id,
            observed_at_ms,
            event_type,
            family,
            protocol,
            local_address,
            local_port,
            remote_address,
            remote_port,
            state,
            previous_state,
            inode,
            tx_queue_bytes,
            rx_queue_bytes
        FROM socket_events
        ORDER BY observed_at_ms DESC, id DESC
        LIMIT ?;
    )sql";

    static constexpr const char* selectProcesses = R"sql(
        SELECT
            pid,
            start_time_ticks,
            uid,
            username,
            name,
            executable,
            command_line
        FROM event_processes
        WHERE event_id = ?
        ORDER BY id;
    )sql";

    Statement eventStatement {database_, selectEvents};
    Statement processStatement {database_, selectProcesses};

    requireBind(database_, sqlite3_bind_int64(
        eventStatement.get(),
        1,
        static_cast<sqlite3_int64>(limit)
    ));

    std::vector<StoredSocketEvent> storedEvents;

    int eventResult = SQLITE_ROW;
    while ((eventResult = sqlite3_step(eventStatement.get()))
        == SQLITE_ROW) {
        StoredSocketEvent stored;
        stored.id = sqlite3_column_int64(eventStatement.get(), 0);

        auto& event = stored.event;
        auto& socket = event.observation.socket;

        event.observed_at = fromEpochMilliseconds(
            sqlite3_column_int64(eventStatement.get(), 1)
        );
        event.type = eventTypeFromText(
            columnText(eventStatement.get(), 2)
        );
        socket.family = familyFromText(
            columnText(eventStatement.get(), 3)
        );
        socket.protocol = protocolFromText(
            columnText(eventStatement.get(), 4)
        );
        socket.local.address = columnText(eventStatement.get(), 5);
        socket.local.port = static_cast<std::uint16_t>(
            sqlite3_column_int(eventStatement.get(), 6)
        );
        socket.remote.address = columnText(eventStatement.get(), 7);
        socket.remote.port = static_cast<std::uint16_t>(
            sqlite3_column_int(eventStatement.get(), 8)
        );
        socket.state = stateFromText(
            columnText(eventStatement.get(), 9)
        );

        if (sqlite3_column_type(eventStatement.get(), 10)
            != SQLITE_NULL) {
            event.previous_state = stateFromText(
                columnText(eventStatement.get(), 10)
            );
        }

        socket.inode = static_cast<std::uint64_t>(
            sqlite3_column_int64(eventStatement.get(), 11)
        );
        socket.tx_queue_bytes = static_cast<std::uint64_t>(
            sqlite3_column_int64(eventStatement.get(), 12)
        );
        socket.rx_queue_bytes = static_cast<std::uint64_t>(
            sqlite3_column_int64(eventStatement.get(), 13)
        );

        sqlite3_stmt* processHandle = processStatement.get();
        requireBind(database_, sqlite3_bind_int64(
            processHandle, 1, stored.id));

        int processResult = SQLITE_ROW;
        while ((processResult = sqlite3_step(processHandle))
            == SQLITE_ROW) {
            ProcessInfo process;
            process.pid = sqlite3_column_int(processHandle, 0);

            if (sqlite3_column_type(processHandle, 1)
                != SQLITE_NULL) {
                process.start_time_ticks =
                    static_cast<std::uint64_t>(
                        sqlite3_column_int64(processHandle, 1)
                    );
            }

            if (sqlite3_column_type(processHandle, 2)
                != SQLITE_NULL) {
                process.uid = static_cast<unsigned int>(
                    sqlite3_column_int64(processHandle, 2)
                );
            }

            process.username = columnText(processHandle, 3);
            process.name = columnText(processHandle, 4);
            process.executable = columnText(processHandle, 5);
            process.command_line = columnText(processHandle, 6);

            event.observation.owners.push_back(
                std::move(process)
            );
        }

        if (processResult != SQLITE_DONE) {
            throwDatabaseError(database_, "SQLite select processes");
        }

        if (sqlite3_reset(processHandle) != SQLITE_OK) {
            throwDatabaseError(database_, "SQLite reset process query");
        }

        if (sqlite3_clear_bindings(processHandle) != SQLITE_OK) {
            throwDatabaseError(database_, "SQLite clear process query");
        }

        storedEvents.push_back(std::move(stored));
    }

    if (eventResult != SQLITE_DONE) {
        throwDatabaseError(database_, "SQLite select events");
    }

    return storedEvents;
}

std::vector<StoredAlert> SQLiteEventRepository::recentAlerts(
    const std::size_t limit,
    const int minimumRiskScore) const
{
    if (limit == 0U) {
        return {};
    }

    if (minimumRiskScore < 0 || minimumRiskScore > 100) {
        throw std::invalid_argument {
            "minimum risk score must be between 0 and 100"
        };
    }

    if (limit > static_cast<std::size_t>(
            std::numeric_limits<sqlite3_int64>::max())) {
        throw std::length_error {"SQLite query limit is too large"};
    }

    static constexpr const char* selectAlerts = R"sql(
        SELECT
            a.id,
            a.event_id,
            a.detected_at_ms,
            a.rule_id,
            a.title,
            a.reason,
            a.risk_score,
            a.severity,
            s.observed_at_ms,
            s.event_type,
            s.family,
            s.protocol,
            s.local_address,
            s.local_port,
            s.remote_address,
            s.remote_port,
            s.state,
            s.previous_state,
            s.inode,
            s.tx_queue_bytes,
            s.rx_queue_bytes
        FROM alerts AS a
        INNER JOIN socket_events AS s ON s.id = a.event_id
        WHERE a.risk_score >= ?
        ORDER BY a.detected_at_ms DESC, a.id DESC
        LIMIT ?;
    )sql";

    static constexpr const char* selectProcesses = R"sql(
        SELECT
            pid,
            start_time_ticks,
            uid,
            username,
            name,
            executable,
            command_line
        FROM event_processes
        WHERE event_id = ?
        ORDER BY id;
    )sql";

    static constexpr const char* selectEvidence = R"sql(
        SELECT detail
        FROM alert_evidence
        WHERE alert_id = ?
        ORDER BY position, id;
    )sql";

    Statement alertStatement {database_, selectAlerts};
    Statement processStatement {database_, selectProcesses};
    Statement evidenceStatement {database_, selectEvidence};

    requireBind(database_, sqlite3_bind_int(
        alertStatement.get(), 1, minimumRiskScore));
    requireBind(database_, sqlite3_bind_int64(
        alertStatement.get(),
        2,
        static_cast<sqlite3_int64>(limit)
    ));

    std::vector<StoredAlert> storedAlerts;

    int alertResult = SQLITE_ROW;
    while ((alertResult = sqlite3_step(alertStatement.get()))
        == SQLITE_ROW) {
        StoredAlert stored;
        stored.id = sqlite3_column_int64(alertStatement.get(), 0);
        stored.event_id = sqlite3_column_int64(
            alertStatement.get(), 1);

        auto& alert = stored.alert;
        alert.detected_at = fromEpochMilliseconds(
            sqlite3_column_int64(alertStatement.get(), 2)
        );
        alert.rule_id = columnText(alertStatement.get(), 3);
        alert.title = columnText(alertStatement.get(), 4);
        alert.reason = columnText(alertStatement.get(), 5);
        alert.risk_score = sqlite3_column_int(
            alertStatement.get(), 6);
        alert.severity = alertSeverityFromString(
            columnText(alertStatement.get(), 7)
        );

        auto& event = alert.source_event;
        auto& socket = event.observation.socket;

        event.observed_at = fromEpochMilliseconds(
            sqlite3_column_int64(alertStatement.get(), 8)
        );
        event.type = eventTypeFromText(
            columnText(alertStatement.get(), 9)
        );
        socket.family = familyFromText(
            columnText(alertStatement.get(), 10)
        );
        socket.protocol = protocolFromText(
            columnText(alertStatement.get(), 11)
        );
        socket.local.address = columnText(
            alertStatement.get(), 12);
        socket.local.port = static_cast<std::uint16_t>(
            sqlite3_column_int(alertStatement.get(), 13)
        );
        socket.remote.address = columnText(
            alertStatement.get(), 14);
        socket.remote.port = static_cast<std::uint16_t>(
            sqlite3_column_int(alertStatement.get(), 15)
        );
        socket.state = stateFromText(
            columnText(alertStatement.get(), 16)
        );

        if (sqlite3_column_type(alertStatement.get(), 17)
            != SQLITE_NULL) {
            event.previous_state = stateFromText(
                columnText(alertStatement.get(), 17)
            );
        }

        socket.inode = static_cast<std::uint64_t>(
            sqlite3_column_int64(alertStatement.get(), 18)
        );
        socket.tx_queue_bytes = static_cast<std::uint64_t>(
            sqlite3_column_int64(alertStatement.get(), 19)
        );
        socket.rx_queue_bytes = static_cast<std::uint64_t>(
            sqlite3_column_int64(alertStatement.get(), 20)
        );

        sqlite3_stmt* processHandle = processStatement.get();
        requireBind(database_, sqlite3_bind_int64(
            processHandle, 1, stored.event_id));

        int processResult = SQLITE_ROW;
        while ((processResult = sqlite3_step(processHandle))
            == SQLITE_ROW) {
            ProcessInfo process;
            process.pid = sqlite3_column_int(processHandle, 0);

            if (sqlite3_column_type(processHandle, 1)
                != SQLITE_NULL) {
                process.start_time_ticks =
                    static_cast<std::uint64_t>(
                        sqlite3_column_int64(processHandle, 1)
                    );
            }

            if (sqlite3_column_type(processHandle, 2)
                != SQLITE_NULL) {
                process.uid = static_cast<unsigned int>(
                    sqlite3_column_int64(processHandle, 2)
                );
            }

            process.username = columnText(processHandle, 3);
            process.name = columnText(processHandle, 4);
            process.executable = columnText(processHandle, 5);
            process.command_line = columnText(processHandle, 6);
            event.observation.owners.push_back(std::move(process));
        }

        if (processResult != SQLITE_DONE) {
            throwDatabaseError(database_, "SQLite select alert processes");
        }

        if (sqlite3_reset(processHandle) != SQLITE_OK) {
            throwDatabaseError(
                database_,
                "SQLite reset alert process query"
            );
        }

        if (sqlite3_clear_bindings(processHandle) != SQLITE_OK) {
            throwDatabaseError(
                database_,
                "SQLite clear alert process query"
            );
        }

        sqlite3_stmt* evidenceHandle = evidenceStatement.get();
        requireBind(database_, sqlite3_bind_int64(
            evidenceHandle, 1, stored.id));

        int evidenceResult = SQLITE_ROW;
        while ((evidenceResult = sqlite3_step(evidenceHandle))
            == SQLITE_ROW) {
            alert.evidence.push_back(
                columnText(evidenceHandle, 0)
            );
        }

        if (evidenceResult != SQLITE_DONE) {
            throwDatabaseError(database_, "SQLite select alert evidence");
        }

        if (sqlite3_reset(evidenceHandle) != SQLITE_OK) {
            throwDatabaseError(
                database_,
                "SQLite reset alert evidence query"
            );
        }

        if (sqlite3_clear_bindings(evidenceHandle) != SQLITE_OK) {
            throwDatabaseError(
                database_,
                "SQLite clear alert evidence query"
            );
        }

        storedAlerts.push_back(std::move(stored));
    }

    if (alertResult != SQLITE_DONE) {
        throwDatabaseError(database_, "SQLite select alerts");
    }

    return storedAlerts;
}

std::size_t SQLiteEventRepository::deleteEventsOlderThan(
    const std::chrono::system_clock::time_point cutoff)
{
    Statement statement {
        database_,
        "DELETE FROM socket_events WHERE observed_at_ms < ?;"
    };

    requireBind(database_, sqlite3_bind_int64(
        statement.get(), 1, toEpochMilliseconds(cutoff)));

    if (sqlite3_step(statement.get()) != SQLITE_DONE) {
        throwDatabaseError(database_, "SQLite delete old events");
    }

    return static_cast<std::size_t>(sqlite3_changes(database_));
}

std::size_t SQLiteEventRepository::eventCount() const
{
    return readCount(
        database_,
        "SELECT COUNT(*) FROM socket_events;"
    );
}

std::size_t SQLiteEventRepository::processCount() const
{
    return readCount(
        database_,
        "SELECT COUNT(*) FROM event_processes;"
    );
}

std::size_t SQLiteEventRepository::alertCount() const
{
    return readCount(
        database_,
        "SELECT COUNT(*) FROM alerts;"
    );
}

} // namespace netwatch

