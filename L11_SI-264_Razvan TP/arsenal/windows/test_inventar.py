from arsenal.windows.inventar import Proces, Eveniment, Inventar


def test_proces_din_temp_e_suspect():
    p = Proces(1, "x.exe", "ana", "C:\\Users\\ana\\AppData\\Local\\Temp\\x.exe")
    assert p.e_suspect() is True


def test_proces_din_windows_nu_e_suspect():
    p = Proces(2, "svchost.exe", "SYSTEM", "C:\\Windows\\System32\\svchost.exe")
    assert p.e_suspect() is False


def test_eveniment_suspect():
    e1 = Eveniment(4625, "warning", "Security", "admin", "Logon failed")
    e2 = Eveniment(1000, "critical", "System", "SYSTEM", "Critical error")
    e3 = Eveniment(4624, "information", "Security", "ana", "Logon success")
    assert e1.e_suspect() is True
    assert e2.e_suspect() is True
    assert e3.e_suspect() is False


def test_inventar_interogari():
    p1 = Proces(1, "bad.exe", "ana", r"C:\Users\ana\AppData\Roaming\bad.exe")
    p2 = Proces(2, "good.exe", "SYSTEM", r"C:\Windows\good.exe")
    inv = Inventar([p1, p2])
    assert len(inv) == 2
    assert inv.suspecte() == [p1]
    assert inv.pe_user() == {"ana": ["bad.exe"], "SYSTEM": ["good.exe"]}