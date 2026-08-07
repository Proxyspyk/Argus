import io

from argus.ui import ARGUS_EYE_ART, ARGUS_TITLE, EyeSpinner, print_banner


def test_print_banner_writes_title_and_art():
    buf = io.StringIO()
    print_banner(stream=buf)
    output = buf.getvalue()
    assert ARGUS_TITLE in output
    assert "●" in ARGUS_EYE_ART  # a pupila do olho está presente na arte


def test_spinner_enter_exit_does_not_raise_without_tty():
    buf = io.StringIO()  # StringIO não tem isatty()=True, então não deve nem tentar renderizar
    with EyeSpinner(interval=0.01, stream=buf) as eye:
        eye.status("testando")
    # não deve lançar exceção, thread deve encerrar corretamente
    assert True


def test_spinner_log_writes_message_even_without_tty():
    buf = io.StringIO()
    with EyeSpinner(interval=0.01, stream=buf) as eye:
        eye.log("mensagem de teste")
    assert "mensagem de teste" in buf.getvalue()
