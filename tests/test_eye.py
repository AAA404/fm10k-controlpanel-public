import copy
import csv
import io

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from fm10k_controlpanel.app import create_app
from fm10k_controlpanel.board import HardwareError
from fm10k_controlpanel.eye import EyeRequest, export_csv, merge_chunk, validate_chunk
from fm10k_controlpanel.optics import power_for_epl
from fm10k_controlpanel.simulator import MockConfigd


def sample(offset=0, columns=4, done=33, state="complete"):
    return {"id":"a"*32,"source":"serdes-hardware","signal_source":"external","state":state,"port":13,"epl":5,"lane":2,
            "speed_mbps":25000,"x_points":33,"y_points":32,"x_resolution":16,"y_step":8,
            "y_min":-128,"dwell_bits":100000,"columns_done":done,"column_offset":offset,
            "errors":[[0]*32 for _ in range(columns)],"started_at":1700000000.5,
            "elapsed_ms":10000,"restored":True,"restore_failed":False,"error":"",
            "measurement":"offset-sampler-xor","vertical_unit":"DAC"}


def test_pages_need_every_measured_column_before_completion():
    value=merge_chunk(None,sample())
    assert value["state"]=="reading" and value["metrics"] is None
    for offset in range(4,33,4): value=merge_chunk(value,sample(offset,min(4,33-offset)))
    assert value["state"]=="complete" and len(value["errors"])==33
    assert value["metrics"]["eye_width_ui"]==2 and value["metrics"]["width_clipped"]
    assert value["metrics"]["center_errors"]==0 and value["metrics"]["detection_floor"]==1e-5
    rows=list(csv.reader(io.StringIO(export_csv(value))))
    assert len(rows)==33*32+1
    assert rows[1][5:10]==["-1.0","-128","0","100000","0.0"]
    assert rows[-1][5:7]==["1.0","120"]


def test_measurement_pages_reject_missing_changed_or_cross_lane_values():
    value=merge_chunk(None,sample())
    for changes in ({"column_offset":5},{"lane":1},{"source":"simulator"},{"signal_source":"internal_prbs31_loopback"},{"started_at":1700000001},
                    {"speed_mbps":10000},{"dwell_scale":2},{"phase_multiplier":4}):
        part=sample(4);part.update(changes)
        with pytest.raises(HardwareError): merge_chunk(value,part)
    part=sample();part["errors"][0][0]=1
    with pytest.raises(HardwareError):merge_chunk(value,part)


def test_partial_csv_preserves_acquisition_and_restoration_status():
    value=merge_chunk(None,sample(columns=2,done=2,state="cancelled"))
    rows=list(csv.DictReader(io.StringIO(export_csv(value))))
    assert len(rows)==2*32
    assert all(row["state"]=="cancelled" and row["restored"]=="True" and
               row["columns_done"]=="2" and row["x_points"]=="33" for row in rows)


@pytest.mark.parametrize("changes", [
    {"x_points":32},{"y_points":31},{"dwell_bits":True},{"source":"unknown"},
    {"restored":False},{"restore_failed":True},{"columns_done":32},{"epl":6},
    {"errors":[[None]*32]},{"errors":[[-1]*32]},{"errors":[[True]*32]},
    {"signal_source":"unknown"},
])
def test_bad_metadata_and_incomplete_scans_never_pass(changes):
    value=sample();value.update(changes)
    with pytest.raises(HardwareError):validate_chunk(value)


@pytest.mark.parametrize("parameters", [{"lane":True},{"lane":4},{"lane":0,"y_step":True},
    {"lane":0,"dwell_bits":100},{"lane":0,"register":23},{"lane":0,"request_id":"../bad"},
    {"lane":0,"signal_source":"unqualified"}])
def test_scan_requests_are_fixed_and_strict(parameters):
    with pytest.raises(ValidationError):EyeRequest(**parameters)


def test_power_mapping_zero_and_freshness():
    module={"mpo":2,"rx_power_quality":"valid","rx_power_sampled_at":100,
            "power_source":"cxp-rx-page1","tx_power_quality":"unsupported",
            "rx_power":[{"channel":c,"raw":c*1000} for c in range(12)]}
    result=power_for_epl(module,6,101)
    assert result["quality"]=="valid" and [x["module_channel"] for x in result["channels"]]==[4,5,6,7]
    assert result["channels"][0]["microwatts"]==400
    assert result["channels"][0]["dbm"]==pytest.approx(-3.9794000867)
    assert power_for_epl(module,5,101)["channels"][0]["dbm"] is None
    assert power_for_epl(module,6,116)["quality"]=="stale"
    module["rx_power"][0]["channel"]=1
    assert power_for_epl(module,6,101)["quality"]=="unavailable"


def test_authenticated_api_lifecycle_cancellation_and_exports(tmp_path):
    now=[1000.0]
    backend=MockConfigd(tmp_path,clock=lambda:now[0])
    backend.configuration.ports[1].enabled=True
    backend.configuration.ports[1].pvid=1
    before=copy.deepcopy(backend.configuration.model_dump())
    app=create_app(state_dir=tmp_path,backend=backend)
    with TestClient(app) as client:
        assert client.get('/api/v1/optics/eye').status_code==401
        auth=client.post('/api/v1/auth/setup',json={"username":"fixture","password":"eye-test-password-123"})
        assert auth.status_code==200
        assert client.get('/api/v1/optics/eye').json()["state"]=="idle"
        assert client.post('/api/v1/optics/ports/1/eye',json={"lane":0}).status_code==403
        client.headers['x-csrf-token']=auth.json()['csrf']
        response=client.post('/api/v1/optics/ports/1/eye',json={"lane":0,"request_id":"a"*32,"x_resolution":16,"y_step":8,"dwell_bits":100000})
        assert response.status_code==202,response.text
        assert response.json()["source"]=="simulator"
        now[0]+=2
        for _ in range(4): value=client.get('/api/v1/optics/eyes/'+'a'*32).json()
        assert value["state"]=="complete" and len(value["errors"])==33
        for format in ('json','csv'):
            response=client.get('/api/v1/optics/eyes/'+'a'*32+'/export?format='+format)
            assert response.status_code==200
            assert 'attachment' in response.headers['content-disposition']
            assert response.headers['cache-control']=='no-store'
        response=client.post('/api/v1/optics/ports/1/eye',json={"lane":0,"request_id":"b"*32})
        assert response.status_code==202
        response=client.post('/api/v1/optics/eyes/'+'b'*32+'/cancel',json={})
        assert response.status_code==202 and response.json()["state"]=="cancelled"
        assert backend.configuration.model_dump()==before
