# netKit

Rust ile geliştirilen, uygulamalara gömülebilen ağ yakalama ve protokol analiz framework'ü. Ethernet ve Wi-Fi kayıtlarından bağlantı, cihaz gözlemi, uygulama mesajı ve tanılama olayları üretir. CLI adı **`netkit`**, proje adı **netKit**.

Kütüphane, CLI ve C ABI aynı analiz motorunu kullanır. Çekirdek Rust'tır; C++ uygulamaları [C başlığı](include/netkit.h) üzerinden bağlanır. Ürün çekirdeğinde C++ gerekmiyor. PCAP/PCAPNG analizi için yakalama sürücüsü gerekmez.

## Çalıştırma

Rust 1.86+ ve platformun C linker'ı gerekir. Windows'ta Visual Studio C++ Build Tools, Linux/macOS'ta normal geliştirme araçları yeterlidir.

```powershell
cargo build --release --workspace
.\target\release\netkit.exe doctor
.\target\release\netkit.exe protocols
.\target\release\netkit.exe analyze tests\fixtures\clinical-network.pcapng
.\target\release\netkit.exe analyze tests\fixtures\clinical-network.pcapng --workers 4 --format jsonl
```

Linux/macOS'ta aynı komutların executable yolu `./target/release/netkit` olur. PATH'e kurulum:

```text
cargo install --path crates/netkit-cli --locked
netkit --help
```

Windows canlı yakalama, ayrıca kurulan [Npcap](https://npcap.com/guide/npcap-devguide.html) kullanır. netKit, Npcap SDK'sı olmadan derlenir ve `wpcap.dll` dosyasını çalışma anında yükler. Npcap bu depoyla dağıtılmaz. Linux'ta libpcap, macOS'ta sistem libpcap kütüphanesi kullanılır. Arayüz açma yetkisi işletim sistemi ve sürücü ayarına bağlıdır.

## Komutlar

```text
netkit interfaces
netkit capture --all-interfaces --duration 60 --output network.pcapng --format jsonl
netkit capture -i 1 -i 2 --workers 4
netkit capture -i 1 --filter "host 192.168.1.37 and tcp" --count 1000
netkit capture -i 2 --monitor --duration 30 --packets
netkit devices --all-interfaces
netkit flows --read tests/fixtures/clinical-network.pcapng
netkit analyze network.pcapng --host 192.168.1.37 --format json
netkit read network.pcapng --protocol hl7
netkit analyze network.pcapng --decode-as astm
netkit decode tests/fixtures/synthetic.hl7 --protocol hl7
netkit config
netkit benchmark tests/fixtures/scale.pcapng --iterations 100 --format json
```

Varsayılan canlı yakalamada IP/port filtresi yoktur. `--filter` sürücüde BPF uygular; `--host` belirli adresi seçer. `--protocol` yalnızca çıktı mesajlarını seçer, `--decode-as` çözücüyü zorlar. `--packets` IP paketlerinin katman özetlerini de verir. `--output` ham PCAPNG kaydeder; var olan dosyayı değiştirmek için ayrıca `--overwrite` gerekir. `Ctrl+C` kuyruğu boşaltır ve çıktıyı kapatır.

`devices` gözlenen IP ve kimlik iddialarını verir; `flows` iki yönlü IP/port konuşmalarını, sayaçları ve bulunan protokolleri verir. Hedef olarak görülen bir IP, çevrimiçi cihazın kesin kanıtı değildir; `evidence` alanını kontrol edin.

Açık port kontrolü, pasif yakalamadan ayrı ve açıkça çağrılan komutlardır:

```text
netkit discover --network 192.168.1.0/24 --ports 80,443 --rate 50
netkit scan --target 192.168.1.37 --ports 1-65535 --tcp --rate 100
netkit scan --target 192.168.1.37 --ports 53,123 --udp
```

TCP bağlantısı ve UDP yanıtı kanıt olarak raporlanır. UDP sessizliği `open_or_filtered`, TCP zaman aşımı `no_response` olur. Tarama kapsamı, hız, eşzamanlılık ve toplam deneme sayısı sınırlıdır. Normal `capture` ve `devices` komutları tarama paketi göndermez.

## Görünürlük

Tüm IP/portları **arayüze ulaşan paketler içinde** işler. Switch üzerindeki başka iki cihazın unicast trafiğini görmek için SPAN/mirror, TAP veya trafiğin geçtiği bir gözlem noktası gerekir. Aynı ağa bağlı olmak bütün konuşmaları görünür yapmaz.

Wi-Fi normal modda çoğunlukla Ethernet biçiminde sunulur. Ham 802.11/Radiotap ve monitor modu donanım/sürücü desteğine bağlıdır; monitor moduna geçiş Wi-Fi bağlantısını kesebilir. Çoklu arayüz yakalama her arayüzü ayrı açar; kaynak kimliğini korur. Linux `any` arayüzü ayrıca seçilebilir; `--all-interfaces` mükerrer kayıtları azaltmak için `any` yerine açık arayüzleri seçer. Aynı paket farklı gözlem noktalarında görülürse otomatik olarak birleştirilmez.

Şifreli içerik kendiliğinden çözülmez. Yerleşik TLS ve QUIC çözümlemesi görünür metadata ile sınırlıdır. Ayrı kurulu TShark ile geniş protokol kapsamı ve desteklenen oturumlar için keylog kullanılabilir:

```text
netkit deep network.pcapng --keylog session.keylog --include-sensitive --format jsonl
```

Bu komut harici TShark JSON çıktısını geçirir; yerleşik olay şeması ve maskeleme uygulanmaz. [Destek matrisi](docs/SUPPORT.md) kapsamı ve sınırlamaları ayrıntılı gösterir.

## Rust entegrasyonu

```toml
[dependencies]
netkit = { path = "../netKit/crates/netkit" }
serde_json = "1"
```

```rust
use netkit::{Engine, EngineConfig, Result, pcap::CaptureReader};
use std::{fs::File, io::BufReader};

fn main() -> Result<()> {
    let mut engine = Engine::new(EngineConfig::default())?;
    let mut input = CaptureReader::new(
        BufReader::new(File::open("network.pcapng")?), "sensor-a"
    )?;
    while let Some(packet) = input.next_packet()? {
        for event in engine.ingest(&packet) {
            println!("{}", serde_json::to_string(&event)?);
        }
    }
    for event in engine.finish() {
        println!("{}", serde_json::to_string(&event)?);
    }
    Ok(())
}
```

Uygulama kendi `Packet` kaynağını sağlayabilir, `capture::Pcap` ile canlı arayüz açabilir veya `pipeline::AnalysisPool` kullanabilir. `Decoder` / `DecodeSession` trait'leri ile özel protokol eklenir. Hazır bir uygulama mesajı `Engine::decode_message` ile ağ açmadan çözülür. [API ve mimari](docs/ARCHITECTURE.md), [çalışır Rust örnekleri](crates/netkit/examples), [C++ örneği](examples/cpp/main.cpp).

```powershell
cargo run -p netkit --example decode
cmd /c tools\build_cpp.cmd
python tools\verify_ffi.py
```

## Doğrulama ve mevcut durum

Kodda paket okuyucu/yazıcı, canlı yakalama arka ucu, akış motoru, yerleşik çözücüler, sınırlı paralel işlem hattı, aktif tarama, CLI ve C ABI bulunur. Bu, bütün standartların ve cihaz varyantlarının eksiksiz desteklendiği anlamına gelmez. Özellikle medikal protokoller yapısal olarak çözülür; üretici profili uygunluk onayı verilmez.

Windows x64 üzerinde sentetik kayıtlar, Rust testleri, gerçek DLL üzerinden ABI ve C++ derlemesi doğrulandı. Gerçek Npcap adaptörü, Linux/macOS canlı yakalama, TShark entegrasyonu, 24 saat donanım testi ve klinik cihaz karşılaştırmaları bu ortamda doğrulanmadı. Üç platform için CI ve fuzz iş akışları depoda yer alır; dosyalarının bulunması bu işlerin çalıştığı anlamına gelmez. Ayrıntılar [doğrulama kaydında](docs/VALIDATION.md).

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
cargo doc --workspace --no-deps
python tools/validate.py --seconds 120
```

Varsayılan çıktıda HL7 segmentleri, ASTM kayıtları, POCT XML alanları, DICOM dataset değerleri ve HTTP başlık değerleri maskelenir. `--include-sensitive` veya `EngineConfig.include_sensitive` ayrıntıları açar. Ham PCAPNG, IP/MAC/hostname, mesaj kontrol ID'leri ve özel çözücü çıktıları bu maskenin kapsamında değildir. Maskeleme bir anonimleştirme veya mevzuat uygunluğu garantisi değildir. Depodaki test verileri sentetiktir.

## Lisans

netKit kodu **MIT OR Apache-2.0**: [MIT](LICENSE-MIT), [Apache-2.0](LICENSE-APACHE). Ticari entegrasyona uygundur. Bağımlılıklar kendi lisanslarını korur; Npcap ve TShark ayrıca temin edilir. [Katkı rehberi](CONTRIBUTING.md), [güvenlik bildirimi](SECURITY.md).
