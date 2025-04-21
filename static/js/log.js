// static/js/log.js

const logTranslations = {
    "Bütün görevler başlatıldı mı?": {
      tr: "Bütün görevler başlatıldı mı?",
      en: "Have all tasks been started?",
      de: "Wurden alle Aufgaben gestartet?",
    },
    "Modem aktif mi": {
      tr: "Cihaz bağlantısı kesildi",
      en: "Device disconnected",
      de: "Verbindung zum Gerät unterbrochen",
    },
    "Enerji değeri okundu": {
      tr: "Enerji değeri okundu",
      en: "Energy value read",
      de: "Energiewert gelesen",
    },
  };
  
  function translateLog(tag, lang) {
    return logTranslations[tag]?.[lang] || tag;
  }
  