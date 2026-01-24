#include "hardware.h"
#include <FspTimer.h>

LiquidCrystal_I2C lcd(0x27, 16, 2);

// ------ TIMER INTERRUPT BUZZER (1ms tick) ------- 
static FspTimer beepTimer;

struct BeepStep { int freq; int ms; };

//  beep (massimo 10 step)
static volatile bool buzzerActive = false;
static volatile bool buzzerUpdate = false;
static volatile int  buzzerFreq = 0;

static volatile int stepRemaining = 0;
static volatile int stepIndex = 0;
static volatile int seqLenVol = 0;

static BeepStep seq[10];


void initLedsAndBuzzer() {
  pinMode(A0, OUTPUT); // verde
  pinMode(A1, OUTPUT); // giallo
  pinMode(A2, OUTPUT); // rosso
  pinMode(A3, OUTPUT); // buzzer

  allOff();
}


// ISR: 1ms tick
static void timer_callback(timer_callback_args_t *p_args) {
  (void)p_args;

  if (!buzzerActive) return;

  if (stepRemaining > 0) {
    stepRemaining--;
    return;
  }

  stepIndex++;
  if (stepIndex >= seqLenVol) {
    buzzerActive = false;
    buzzerFreq = 0;
    buzzerUpdate = true;
    return;
  }

  buzzerFreq = seq[stepIndex].freq;
  stepRemaining = seq[stepIndex].ms;
  buzzerUpdate = true;
}

// timer a 1000 Hz (1ms)
bool initTimer1ms() {
  uint8_t timer_type = GPT_TIMER;
  int8_t tindex = FspTimer::get_available_timer(timer_type);
  if (tindex < 0) tindex = FspTimer::get_available_timer(timer_type, true);
  if (tindex < 0) return false;

  FspTimer::force_use_of_pwm_reserved_timer();

  if (!beepTimer.begin(TIMER_MODE_PERIODIC, timer_type, tindex, 1000.0f, 0.0f, timer_callback)) return false;
  if (!beepTimer.setup_overflow_irq()) return false;
  if (!beepTimer.open()) return false;
  if (!beepTimer.start()) return false;

  return true;
}


void initBeepTimer() {
  initTimer1ms();
}


void handleBuzzer() {
  if (!buzzerUpdate) return;

  noInterrupts();
  bool active = buzzerActive;
  int f = buzzerFreq;
  buzzerUpdate = false;
  interrupts();

  if (!active || f <= 0) noTone(A3);
  else tone(A3, f);
}

// Avvia sequenza in modo atomico (sicuro contro ISR)
static void startBeepSequence(const BeepStep* s, int len) {
  if (len > 10) len = 10;

  noInterrupts();
  for (int i = 0; i < len; i++) seq[i] = s[i];

  seqLenVol = len;
  stepIndex = 0;
  stepRemaining = seq[0].ms;
  buzzerFreq = seq[0].freq;
  buzzerActive = true;
  buzzerUpdate = true;
  interrupts();
}


void beepClick() {
  const BeepStep s[] = {
    {300, 30},
    {0,   10}
  };
  startBeepSequence(s, 2);
}


void beepOk() {
  const BeepStep s[] = {
    {1500, 120},
    {0,    20}
  };
  startBeepSequence(s, 2);
}


void beepDenied() {
  const BeepStep s[] = {
    {1000, 200}, {0, 100},
    {1000, 200}, {0, 100},
    {1000, 200}, {0, 100}
  };
  startBeepSequence(s, 6);
}



void setLeds(bool verde, bool giallo, bool rosso) {
  digitalWrite(A0, verde  ? HIGH : LOW);
  digitalWrite(A1, giallo ? HIGH : LOW);
  digitalWrite(A2, rosso  ? HIGH : LOW);
}

void allOff() {
  setLeds(false, false, false);
  noTone(A3);
}

void showLcd(const String& line1, const String& line2) {
  lcd.setCursor(0, 0);
  lcd.print("                ");   // 16 spazi
  lcd.setCursor(0, 0);
  lcd.print(line1);

  lcd.setCursor(0, 1);
  lcd.print("                ");   // 16 spazi
  lcd.setCursor(0, 1);
  lcd.print(line2);
}


void smartDelay(unsigned long ms) {
  while (ms--) {
    handleBuzzer();      
   mqttClient.poll();   
    delay(1);
  }
}
