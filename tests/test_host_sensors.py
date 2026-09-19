from fm10k_controlpanel.host_sensors import AtomTemperature


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(value))


def test_package_temperature_preferred_over_hotter_core(tmp_path):
    sensor = AtomTemperature(tmp_path, clock=lambda: 100)
    h = tmp_path / "class/hwmon/hwmon0"
    write(h / "name", "coretemp")
    write(h / "temp1_label", "Package id 0")
    write(h / "temp1_input", 44000)
    write(h / "temp2_label", "Core 0")
    write(h / "temp2_input", 49000)
    sample = sensor.sample()
    assert sample["id"] == "atom_cpu" and sample["celsius"] == 44
    assert sample["sampled_at"] == 100 and "Package id 0" in sample["source"]
    (h / "temp1_input").unlink()
    assert sensor.sample()["celsius"] == 49


def test_recognized_soc_dts_fallback_and_stale_timestamp(tmp_path):
    clock = [100]
    sensor = AtomTemperature(tmp_path, clock=lambda:clock[0])
    t = tmp_path / "class/thermal/thermal_zone0"
    write(t / "type", "soc_dts0")
    write(t / "temp", 52000)
    assert sensor.sample()["celsius"] == 52
    clock[0] = 120
    write(t / "temp", "unreadable")
    stale = sensor.sample()
    assert stale["celsius"] == 52 and stale["sampled_at"] == 100 and stale["quality"] == "stale"
    write(t / "temp", 45000)
    assert sensor.sample()["sampled_at"] == 120 and sensor.sample()["quality"] == "valid"


def test_does_not_label_acpi_or_pch_as_cpu(tmp_path):
    write(tmp_path / "class/thermal/thermal_zone0/type", "acpitz")
    write(tmp_path / "class/thermal/thermal_zone0/temp", 51000)
    write(tmp_path / "class/hwmon/hwmon0/name", "pch_cannonlake")
    write(tmp_path / "class/hwmon/hwmon0/temp1_input", 56000)
    sample = AtomTemperature(tmp_path).sample()
    assert sample["celsius"] is None and sample["sampled_at"] is None
    assert sample["quality"] == "unavailable"


def test_cpu_readings_out_of_range_are_unavailable(tmp_path):
    write(tmp_path / "class/thermal/thermal_zone0/type", "x86_pkg_temp")
    for reading in (999000, -99000, "nan"):
        write(tmp_path / "class/thermal/thermal_zone0/temp", reading)
        assert AtomTemperature(tmp_path).sample()["quality"] == "unavailable"
