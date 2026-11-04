package agent

import "testing"

func TestParseQueue(t *testing.T) {
	out := []byte(`{"queue_name": "deferred", "queue_id": "4B1F2C3D4E", "arrival_time": 1700000000, "message_size": 2048, "sender": "a@example.test", "recipients": [{"address": "b@remote.test", "delay_reason": "connect to remote.test[192.0.2.1]:25: Connection timed out"}]}
{"queue_name": "active", "queue_id": "5C2A3B4D5F", "arrival_time": 1700000100, "message_size": 100, "sender": "", "recipients": []}

`)
	list, err := ParseQueue(out)
	if err != nil || len(list) != 2 {
		t.Fatalf("%v %v", list, err)
	}
	if list[0].ID != "4B1F2C3D4E" || list[0].Queue != "deferred" || list[0].Size != 2048 || len(list[0].Recipients) != 1 ||
		list[0].Recipients[0].Reason == "" || list[0].Arrived.Unix() != 1700000000 {
		t.Errorf("%+v", list[0])
	}
	if _, err := ParseQueue([]byte("not json\n")); err == nil {
		t.Error("garbage accepted")
	}
}

func TestCheckQueueIDs(t *testing.T) {
	if err := CheckQueueIDs([]string{"4B1F2C3D4E", "ABCDEF12"}); err != nil {
		t.Error(err)
	}
	for _, bad := range [][]string{nil, {""}, {"-d"}, {"ALL deferred"}, {"abc"}, {"4B1F2C3D4E;rm"}, {"../x"}} {
		if CheckQueueIDs(bad) == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
