#![no_main]

use gateinto::divert::protocol::{Event, ProtocolError, StatusReader};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&split, stream)) = data.split_first() else {
        return;
    };
    let whole = read(&[stream]);
    let (head, tail) = stream.split_at(stream.len() * usize::from(split) / 255);
    assert_eq!(read(&[head, tail]), whole);
    if let Ok(events) = whole {
        let encoded: String = events.iter().map(Event::line).collect();
        assert_eq!(encoded.as_bytes(), stream);
    }
});

fn read(chunks: &[&[u8]]) -> Result<Vec<Event>, ProtocolError> {
    let mut reader = StatusReader::new();
    let mut events = Vec::new();
    for chunk in chunks {
        events.extend(reader.push(chunk)?);
    }
    reader.finish()?;
    Ok(events)
}
