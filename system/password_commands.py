from .password_security import _validate_password_transport

CMD_PASSWD = "passwd"
CMD_CHPASSWD = "chpasswd"
CMD_GETENT = "getent"
CMD_CHAGE = "chage"
CMD_USERMOD = "usermod"
EXPIRE_IMMEDIATELY_VALUE = "0"


def _build_change_password_command() -> list[str]:
    return [CMD_CHPASSWD]


def _build_lock_password_command(username: str, strategy=None) -> list[str]:
    from .linux_password import PasswordCommandStrategy

    if strategy is None:
        strategy = PasswordCommandStrategy.PASSWD

    return (
        [CMD_USERMOD, "-L", username]
        if strategy == PasswordCommandStrategy.USERMOD
        else [CMD_PASSWD, "-l", username]
    )


def _build_unlock_password_command(username: str, strategy=None) -> list[str]:
    from .linux_password import PasswordCommandStrategy

    if strategy is None:
        strategy = PasswordCommandStrategy.PASSWD

    return (
        [CMD_USERMOD, "-U", username]
        if strategy == PasswordCommandStrategy.USERMOD
        else [CMD_PASSWD, "-u", username]
    )


def _build_expire_password_command(username: str) -> list[str]:
    return [CMD_CHAGE, "-d", EXPIRE_IMMEDIATELY_VALUE, username]


def _build_clear_expiration_command(username: str) -> list[str]:
    return [CMD_CHAGE, "-d", "-1", username]


def _build_query_expiration_command(username: str) -> list[str]:
    return [CMD_CHAGE, "-l", username]


def _build_passwd_status_command(username: str) -> list[str]:
    return [CMD_PASSWD, "-S", username]


def _build_aging_command(
    username: str,
    *,
    minimum_days: int | None = None,
    maximum_days: int | None = None,
    warning_days: int | None = None,
    inactive_days: int | None = None,
) -> list[str]:
    command = [CMD_CHAGE]
    if minimum_days is not None:
        command.extend(["-m", str(minimum_days)])
    if maximum_days is not None:
        command.extend(["-M", str(maximum_days)])
    if warning_days is not None:
        command.extend(["-W", str(warning_days)])
    if inactive_days is not None:
        command.extend(["-I", str(inactive_days)])
    command.append(username)
    return command


def _build_user_exists_command(username: str) -> list[str]:
    return [CMD_GETENT, "passwd", username]


def _build_chpasswd_input(username: str, password: str) -> str:
    _validate_password_transport(password)

    return f"{username}:{password}\n"
