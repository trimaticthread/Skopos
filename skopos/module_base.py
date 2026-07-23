"""
Modül temel sınıfı ve kayıt (registry) sistemi.

Yeni bir tool eklemek için:
  1. skopos/modules/ altında yeni bir dosya aç (ör. bloodhound.py)
  2. BaseModule'dan türeyen bir sınıf yaz, @register ile işaretle
  3. name, description, requires alanlarını doldur
  4. build_commands() metodunu implemente et
  5. (opsiyonel) config/default.yaml'daki profillere kendi bloğunu ekle
Başka hiçbir yeri değiştirmene gerek yok; runner modülü otomatik keşfeder.
"""

from abc import ABC, abstractmethod
from collections import namedtuple

# Bir modülün çalıştıracağı tek bir komut.
#   label  : çıktı dosyası / log için kısa etiket (ör. "portscan")
#   argv   : liste halinde komut satırı (shell=False)
#   redact : log/ekranda maskelenecek hassas değerler (ör. parola). Varsayılan None.
Command = namedtuple("Command", ["label", "argv", "redact"])
Command.__new__.__defaults__ = (None,)

# Kayıtlı tüm modüller: {name: sınıf}
REGISTRY = {}


def register(cls):
    """Modül sınıfını registry'ye ekleyen dekoratör."""
    if cls.name in REGISTRY:
        raise ValueError(f"Modül adı çakışması: '{cls.name}' zaten kayıtlı.")
    REGISTRY[cls.name] = cls
    return cls


class BaseModule(ABC):
    # --- Alt sınıfların override etmesi gereken alanlar ---
    name = "base"            # benzersiz modül adı (CLI'da --modules ile kullanılır)
    description = ""         # kısa açıklama (--list-modules çıktısında görünür)
    requires = []            # gereken harici binary'ler, ör. ["nmap"]

    def __init__(self, target, profile_cfg, cfg, ctx):
        """
        target      : hedef (IP / domain / URL)
        profile_cfg : bu modülün seçili profildeki ayarları (dict)
        cfg         : tüm config (wordlist yolları, binary isimleri vb.)
        ctx         : modüller arası paylaşılan çalışma zamanı verisi (dict)
                      ör. nmap açık portları buraya yazar, web modülü okur.
        """
        self.target = target
        self.pcfg = profile_cfg or {}
        self.cfg = cfg
        self.ctx = ctx

    def module_settings(self):
        """config['modules'][self.name] sabit ayarlarını döndürür."""
        return self.cfg.get("modules", {}).get(self.name, {})

    def runtime_requires(self):
        """
        Çalışma anında gereken harici binary listesi.
        Varsayılan olarak statik `requires`; config'e bağlı modüller
        (ör. fuzzing tool seçimi) bunu override edebilir.
        """
        return list(self.requires)

    def extra_args(self):
        """
        Kullanıcının bu modüle geçirdiği ham ekstra parametreler.
        İsimli profil düğmelerinin ÜSTÜNE eklenir; böylece hiçbir tool
        parametresi/kombinasyonu erişilemez kalmaz.
        Kaynak: profil bloğundaki `extra_args` (+ CLI --extra ile enjekte edilen).
        Liste ya da tek string olabilir.
        """
        val = self.pcfg.get("extra_args", [])
        if isinstance(val, str):
            import shlex
            return shlex.split(val)
        return list(val)

    @abstractmethod
    def build_commands(self):
        """Çalıştırılacak Command listesini döndürür."""
        raise NotImplementedError

    def post_process(self, results):
        """
        (Opsiyonel) Komutlar bittikten sonra çağrılır.
        results: [(Command, return_code, çıktı_str), ...]
        Modüller burada çıktı parse edip ctx'e veri yazabilir.
        """
        return None
