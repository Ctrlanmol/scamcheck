# Sample messages for the self-test.
# (text, expected minimum verdict rank)  rank: 0=safe, 1=suspicious, 2=likely scam, 3=scam
SAMPLES = [
    # -- should be safe ------------------------------------------------------
    ("hjkl 0987678", 0),
    ("Hi mom, reached the airport. Will call you in 2 hours, love you!", 0),
    ("Your SBI card shipment BLR1234 will arrive today between 3-5 PM.", 0),

    # -- should be at least suspicious ----------------------------------------
    ("URGENT: Your bank account has been suspended due to unauthorized "
     "transaction. Verify your details immediately at http://202.51.10.7/secure-hdfc-verify", 2),
    ("Your OTP is 448291. Do not share this code with anyone.", 2),
    ("You have won a lottery! Click www.ru-win-prize.xyz to claim", 2),

    # -- outright scam above ---------------------------------------------------
    # -- should be outright scam ----------------------------------------------
    ("Congratulations! You've won a lottery of $500,000. Claim your prize now! "
     "Send $2000 processing fee via UPI to receiver9021@ibl", 3),
    ("This is FedEx: your parcel is held in customs. Pay the $1.99 fee via gift "
     "card to release. Contact us at t.me/parsellhelpdesk", 3),

    # -- multilingual (Hindi/Hinglish: India = biggest victim market) ----------
    ("aaj shaam ko milenge, chai piyenge", 0),
    ("माँ, मैं कल घर आ रहा हूँ, दोपहर में फ़ोन करता हूँ।", 0),
    ("SR is on leave today, cover his shift", 0),
    ("Dear customer aapka KYC expire ho gaya hai. KYC update karein warna "
     "aapka bank account band ho jayega. bit.ly/kyc-now", 2),
    ("Aapka SBI account block ho gaya hai turant verify karein: bit.ly/sbi-safe", 2),
    ("आपका बैंक खाता आज शाम तक बंद कर दिया जाएगा।", 1),
    ("Aap jeet gaye hain! Aapka lucky draw prize ₹25,00,000 claim karein. "
     "Processing fee Rs 4500 bhejein UPI se.", 2),
    ("आप लॉटरी जीत गए हैं! इनाम पाने के लिए 500 रुपये भेजें।", 1),
    ("आप डिजिटल गिरफ्तारी में हैं। साइबर पुलिस के साथ वीडियो कॉल पर बने रहें।", 1),
    ("Part-time job hai, rozana ₹2000 kamai. Telegram join karo aur "
     "recharge karo ₹500.", 1),

    # -- v0.5 playbooks: new schemes -------------------------------------------
    ("I recorded you through your webcam. I have your contacts. Send 0.05 BTC "
     "within 48 hours or I will leak the video to your family and colleagues.", 2),
    ("Your vehicle has an unpaid toll violation of $6.50. Pay within 24 hours "
     "to avoid a $50 late fee: http://dmv-toll-pay.top/eztag", 2),
    ("Dear SBI customer, your YONO app is outdated. Download the new APK from "
     "this link to avoid account block: http://sbi-yono-update.apk.link/install", 2),
    ("2BHK flat for rent in Andheri, 18000/month. Owner is in Dubai. Pay "
     "10000 booking amount to hold the flat, keys will be couriered after "
     "payment.", 1),
    ("Hi Mum, this is my new number. My old phone is broken and I can't call. "
     "Please send 850 urgently for the deposit, don't call just transfer.", 2),

    # -- v0.5 negatives: ordinary business / family messages -------------------
    ("Hi team, please find attached the July invoice. Payment is due in 30 "
     "days as usual. Thanks, Priya from accounts.", 0),
    ("Hi mum, this is my new number, call me when you are free tonight.", 0),
    ("Your toll balance is low, please recharge online or at any counter.", 0),
]

# Multi-message conversations for trajectory analysis
CONVERSATIONS = {
    "pig_butcher": """Stranger: Hi, is this Mr. Wong? from the gym ?
    You: Sorry, wrong number.
    Stranger: Oh sorry! You seem nice though. Can we be friends? I'm Emily, from Hong Kong.
    Stranger: Good morning! How was your day? I was thinking about you.
    Stranger: Good evening dear, finished my yoga class. You are always in my heart.
    Stranger: I really like talking to you, I have never felt a connection like this before.
    Stranger: My uncle is a fund manager. He taught me trading on a crypto platform. Do you want to see?
    Stranger: Register here, link below, my teacher will guide you. I made $3800 today!
    Stranger: Invest USD 500 first, guaranteed profit dear. I'll help you take screenshots.
    Stranger: You need to deposit $5000 more to reach VIP level 3, time is running out!
    Stranger: Withdrawal fee is 15%, pay by USDT and then you can release all funds.
    Stranger: If you don't top up, your earnings will be lost. Don't tell your family or bank about this.""",

    "normal_talk": """Sam: hey did you watch the game last night
    Alex: yeah insane finish! went to overtime
    Sam: totally, see you at practice tomorrow
    Alex: cool, bring the ball
    Sam: will do, later!""",

    # Hinglish fake part-time job (task scam) trajectory -- the #1 scam format
    # for young adults in India (research dossier S4/S6)
    "hinglish_task": """Recruiter: Namaste ji! Part-time job chahiye? Ghar baithe rozana ₹2000
    Recruiter: Rating task karte ho? Amazon ke products ko boost karna hai
    You: kaise? mujhe samajh nahi aaya
    Recruiter: Pehle ₹500 recharge karo, phir task milega, commission 20% daily
    You: paisa khatam ho jayega to?
    Recruiter: Paisa double ho jayega ji, promised. Task complete karo
    Recruiter: Sirf 2 hours level 3 tak pahuncho. Waqt nahi hai, spot confirm karo
    Recruiter: Recharge karo ₹2000 warning: level complete nahi to paisa atka jayega
    Recruiter: Tax lagana hoga withdrawal se pehle, GST bharna padega ₹3500
    Recruiter: Kisi ko batana mat, ye exclusive offer hai sirf aapke liye""",
}

