/*
* Copyright (C) 2020  Aravinth Manivannan <realaravinth@batsense.net>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use crate::errors::{CredsError, CredsResult};
use lazy_static::lazy_static;
use regex::Regex;

/// Check if a string contains profainity
pub fn beep(target: &str) -> CredsResult<()> {
    static PROFAINITY: &'static str = r"[^!@#$%^&*]*(سكس|طيز|شرج|لعق|لحس|مص|تمص|بيضان|ثدي|بز|بزاز|حلمة|مفلقسة|بظر|كس|فرج|شهوة|شاذ|مبادل|عاهرة|جماع|قضيب|زب|لوطي|لواط|سحاق|سحاقية|اغتصاب|خنثي|احتلام|نيك|متناك|متناكة|شرموطة|عرص|خول|قحبة|لبوةbordel|buzna|čumět|čurák|debil|dopiče|doprdele|dršťka|držka|flundra|hajzl|hovno|chcanky|chuj|jebat|kokot|kokotina|koňomrd|kunda|kurva|mamrd|mrdat|mrdka|mrdník|oslošoust|piča|píčus|píchat|pizda|prcat|prdel|prdelka|sračka|srát|šoustat|šulin|vypíčenec|zkurvit|zkurvysyn|zmrd|žrát|anus|bøsserøv|cock|fisse|fissehår|fuck|hestepik|kussekryller|lort|luder|pik|pikhår|pikslugeri|piksutteri|pis|røv|røvhul|røvskæg|røvspræke|shit|analritter|arsch|arschficker|arschlecker|arschloch|bimbo|bratze|bumsen|bonze|dödel|fick|ficken|flittchen|fotze|fratze|hackfresse|hure|hurensohn|ische|kackbratze|kacke|kacken|kackwurst|kampflesbe|kanake|kimme|lümmel|MILF|möpse|morgenlatte|möse|mufti|muschi|nackt|neger|nigger|nippel|nutte|onanieren|orgasmus|penis|pimmel|pimpern|pinkeln|pissen|pisser|popel|poppen|porno|reudig|rosette|schabracke|schlampe|scheiße|scheisser|schiesser|schnackeln|schwanzlutscher|schwuchtel|tittchen|titten|vögeln|vollpfosten|wichse|wichsen|wichser|2g1c|2girls1cup|acrotomophilia|alabamahotpocket|alaskanpipeline|anal|anilingus|anus|apeshit|arsehole|ass|asshole|assmunch|autoerotic|autoerotic|babeland|babybatter|babyjuice|ballgag|ballgravy|ballkicking|balllicking|ballsack|ballsucking|bangbros|bangbus|bareback|barelylegal|barenaked|bastard|bastardo|bastinado|bbw|bdsm|beaner|beaners|beavercleaver|beaverlips|beastiality|bestiality|bigblack|bigbreasts|bigknockers|bigtits|bimbos|birdlock|bitch|bitches|blackcock|blondeaction|blondeonblondeaction|blowjob|blowjob|blowyourload|bluewaffle|blumpkin|bollocks|bondage|boner|boob|boobs|bootycall|brownshowers|brunetteaction|bukkake|bulldyke|bulletvibe|bullshit|bunghole|bunghole|busty|butt|buttcheeks|butthole|cameltoe|camgirl|camslut|camwhore|carpetmuncher|carpetmuncher|chocolaterosebuds|cialis|circlejerk|clevelandsteamer|clit|clitoris|cloverclamps|clusterfuck|cock|cocks|coprolagnia|coprophilia|cornhole|coon|coons|creampie|cum|cumming|cumshot|cumshots|cunnilingus|cunt|darkie|daterape|daterape|deepthroat|deepthroat|dendrophilia|dick|dildo|dingleberry|dingleberries|dirtypillows|dirtysanchez|doggiestyle|doggiestyle|doggystyle|doggystyle|dogstyle|dolcett|domination|dominatrix|dommes|donkeypunch|doubledong|doublepenetration|dpaction|dryhump|dvda|eatmyass|ecchi|ejaculation|erotic|erotism|escort|eunuch|fag|faggot|fecal|felch|fellatio|feltch|femalesquirting|femdom|figging|fingerbang|fingering|fisting|footfetish|footjob|frotting|fuck|fuckbuttons|fuckin|fucking|fucktards|fudgepacker|fudgepacker|futanari|gangbang|gangbang|gaysex|genitals|giantcock|girlon|girlontop|girlsgonewild|goatcx|goatse|goddamn|gokkun|goldenshower|goodpoop|googirl|goregasm|grope|groupsex|g-spot|guro|handjob|handjob|hardcore|hardcore|hentai|homoerotic|honkey|hooker|horny|hotcarl|hotchick|howtokill|howtomurder|hugefat|humping|incest|intercourse|jackoff|jailbait|jailbait|jellydonut|jerkoff|jigaboo|jiggaboo|jiggerboo|jizz|juggs|kike|kinbaku|kinkster|kinky|knobbing|leatherrestraint|leatherstraightjacket|lemonparty|livesex|lolita|lovemaking|makemecome|malesquirting|masturbate|masturbating|masturbation|menageatrois|milf|missionaryposition|mong|motherfucker|moundofvenus|mrhands|muffdiver|muffdiving|nambla|nawashi|negro|neonazi|nigga|nigger|nignog|nimphomania|nipple|nipples|nsfw|nsfwimages|nude|nudity|nutten|nympho|nymphomania|octopussy|omorashi|onecuptwogirls|oneguyonejar|orgasm|orgy|paedophile|paki|panties|panty|pedobear|pedophile|pegging|penis|phonesex|pieceofshit|pikey|pissing|pisspig|pisspig|playboy|pleasurechest|polesmoker|ponyplay|poof|poon|poontang|punany|poopchute|poopchute|porn|porno|pornography|princealbertpiercing|pthc|pubes|pussy|queaf|queef|quim|raghead|ragingboner|rape|raping|rapist|rectum|reversecowgirl|rimjob|rimming|rosypalm|rosypalmandher5sisters|rustytrombone|sadism|santorum|scat|schlong|scissoring|semen|sex|sexcam|sexo|sexy|sexual|sexually|sexuality|shavedbeaver|shavedpussy|shemale|shibari|shit|shitblimp|shitty|shota|shrimping|skeet|slanteye|slut|s&m|smut|snatch|snowballing|sodomize|sodomy|spastic|spic|splooge|sploogemoose|spooge|spreadlegs|spunk|strapon|strapon|strappado|stripclub|styledoggy|suck|sucks|suicidegirls|sultrywomen|swastika|swinger|taintedlove|tastemy|teabagging|threesome|throating|thumbzilla|tiedup|tightwhite|tit|tits|titties|titty|tongueina|topless|tosser|towelhead|tranny|tribadism|tubgirl|tubgirl|tushy|twat|twink|twinkie|twogirlsonecup|undressing|upskirt|urethraplay|urophilia|vagina|venusmound|viagra|vibrator|violetwand|vorarephilia|voyeur|voyeurweb|voyuer|vulva|wank|wetback|wetdream|whitepower|whore|worldsex|wrappingmen|wrinkledstarfish|xx|xxx|yaoi|yellowshowers|yiffy|zoophilia|🖕|bugren|bugri|bugru|ĉiesulino|ĉiesulo|diofek|diofeka|fek|feken|fekfikanto|feklekulo|fekulo|fik|fikado|fikema|fikfek|fiki|fikiĝi|fikiĝu|fikilo|fikklaŭno|fikota|fiku|forfiki|forfikiĝu|forfiku|forfurzu|forpisi|forpisu|furzulo|kacen|kaco|kacsuĉulo|kojono|piĉen|piĉo|zamenfekAsesinato|asno|bastardo|Bollera|Cabrón|Caca|Chupada|Chupapollas|Chupetón|concha|Conchadetumadre|Coño|Coprofagía|Culo|Drogas|Esperma|Fiestadesalchichas|Follador|Follar|Gilipichis|Gilipollas|Hacerunapaja|Haciendoelamor|Heroína|Hijadeputa|Hijaputa|Hijodeputa|Hijoputa|Idiota|Imbécil|infierno|Jilipollas|Kapullo|Lameculos|Maciza|Macizorra|maldito|Mamada|Marica|Maricón|Mariconazo|martillo|Mierda|Nazi|Orina|Pedo|Pendejo|Pervertido|Pezón|Pinche|Pis|Prostituta|Puta|Racista|Ramera|Sádico|Semen|Sexo|Sexooral|Soplagaitas|Soplapollas|Tetasgrandes|Tíabuena|Travesti|Trio|Verga|vetealamierda|Vulva|آبکیر|ارگاسم|برهنه|پورن|پورنو|تجاوز|تخمی|جق|جقی|جلق|جنده|چوچول|حشر|حشری|داف|دودول|ساکزدن|سکس|سکسکردن|سکسی|سوپر|شقکردن|شهوت|شهوتی|شونبول|فیلمسوپر|کس|کسدادن|کسکردن|کسکش|کوس|کون|کوندادن|کونکردن|کونکش|کونی|کیر|کیری|لاپا|لاپایی|لاشی|لخت|لش|منی|هرزه|alfrednussi|bylsiä|haahka|haistapaska|haistavittu|hatullinen|helvetisti|hevonkuusi|hevonpaska|hevonperse|hevonvittu|hevonvitunperse|hitosti|hitto|huorata|hässiä|juostenkustu|jutku|jutsku|jätkä|kananpaska|koiranpaska|kuinesterinperseestä|kulli|kullinluikaus|kuppainen|kusaista|kuseksia|kusettaa|kusi|kusipää|kusta|kyrpiintynyt|kyrpiintyä|kyrpiä|kyrpä|kyrpänaama|kyrvitys|lahtari|lutka|molo|molopää|mulkero|mulkku|mulkvisti|muna|munapää|munaton|mutakuono|mutiainen|naida|nainti|narttu|neekeri|nekru|nuollapersettä|nussia|nussija|nussinta|paljaalla|palli|pallit|paneskella|panettaa|panna|pano|pantava|paska|paskainen|paskamainen|paskanmarjat|paskantaa|paskapuhe|paskapää|paskattaa|paskiainen|paskoa|pehko|pentele|perkele|perkeleesti|persaukinen|perse|perseennuolija|perseetolalla|persereikä|perseääliö|persläpi|perspano|persvako|pilkunnussija|pillu|pillut|pipari|piru|pistää|pyllyvako|reikä|reva|ripsipiirakka|runkata|runkkari|runkkaus|runkku|ryssä|rättipää|saatanasti|suklaaosasto|tavara|toosa|tuhkaluukku|tumputtaa|turpasauna|tussu|tussukka|tussut|vakipano|vetääkäteen|viiksi|vittu|vittuilla|vittuilu|vittumainen|vittuuntua|vittuuntunut|vitun|vitusti|vituttaa|vitutus|äpärä|putaka|putangina|tangina|tangina|burat|bayag|bobo|nognog|tanga|ulol|kantot|anakkangputa|ulol|jakol|baiser|bander|bigornette|bite|bitte|bloblos|bordel|bourré|bourrée|brackmard|branlage|branler|branlette|branleur|branleuse|brouterlecresson|caca|chatte|chiasse|chier|chiottes|clito|clitoris|con|connard|connasse|conne|couilles|cramouille|cul|déconne|déconner|emmerdant|emmerder|emmerdeur|emmerdeuse|enculé|enculée|enculeur|enculeurs|enfoiré|enfoirée|étron|filledepute|filsdepute|folle|foutre|gerbe|gerber|gouine|grandefolle|grogniasse|gueule|jouir|laputaindetamère|MALPT|ménageàtrois|merde|merdeuse|merdeux|meuf|nègre|negro|niquetamère|niquetarace|palucher|pédale|pédé|péter|pipi|pisser|pouffiasse|pousse-crotte|putain|pute|ramoner|sacàfoutre|sacàmerde|salaud|salope|suce|tapette|tanche|teuch|tringler|trique|troncher|trouducul|turlute|zigounette|zizi|noune|osti|criss|crisse|calice|tabarnak|viarge|aand|aandu|balatkar|balatkari|behenchod|betichod|bhadva|bhadve|bhandve|bhangi|bhootnike|bhosad|bhosadike|boobe|chakke|chinaal|chinki|chod|chodu|chodubhagat|chooche|choochi|choope|choot|chootkebaal|chootia|chootiya|chuche|chuchi|chudaap|chudaikhanaa|chudamchudai|chude|chut|chutkachuha|chutkachuran|chutkamail|chutkebaal|chutkedhakkan|chutmaarli|chutad|chutadd|chutan|chutia|chutiya|gaand|gaandfat|gaandmasti|gaandufad|gandfattu|gandu|gashti|gasti|ghassa|ghasti|gucchi|gucchu|harami|haramzade|hawas|hawaskepujari|hijda|hijra|jhant|jhantchaatu|jhantkakeeda|jhantkebaal|jhantkepissu|jhantu|kamine|kaminey|kanjar|kutta|kuttakamina|kuttekiaulad|kuttekijat|kuttiya|loda|lodu|lund|lundchoos|lundkabakkal|lundkhajoor|lundtopi|lundure|maakichut|maal|madarchod|madarchod|madhavchod|moohmeinle|mutth|mutthal|najayaz|najayazaulaad|najayazpaidaish|paki|pataka|patakha|raand|randaap|randi|randirona|saala|saalakutta|saalikutti|saalirandi|suar|suarkelund|suarkiaulad|tatte|tatti|terimaakabhosada|terimaakabobachusu|terimaakibehenchod|terimaakichut|tharak|tharki|tuchuda|balfasz|balfaszok|balfaszokat|balfaszt|barmok|barmokat|barmot|barom|baszik|bazmeg|buksza|bukszák|bukszákat|bukszát|búr|búrok|csöcs|csöcsök|csöcsöket|csöcsöt|fasz|faszfej|faszfejek|faszfejeket|faszfejet|faszok|faszokat|faszt|fing|fingok|fingokat|fingot|franc|francok|francokat|francot|geci|gecibb|gecik|geciket|gecit|kibaszott|kibaszottabb|kúr|kurafi|kurafik|kurafikat|kurafit|kurva|kurvák|kurvákat|kurvát|leggecibb|legkibaszottabb|legszarabb|marha|marhák|marhákat|marhát|megdöglik|pele|pelék|picsa|picsákat|picsát|pina|pinák|pinákat|pinát|pofa|pofákat|pofát|pöcs|pöcsök|pöcsöket|pöcsöt|punci|puncik|segg|seggek|seggeket|segget|seggfej|seggfejek|seggfejeket|seggfejet|szajha|szajhák|szajhákat|szajhát|szar|szarabb|szarik|szarok|szarokat|szart|allupato|ammucchiata|anale|arrapato|arrusa|arruso|assatanato|bagascia|bagassa|bagnarsi|baldracca|balle|battere|battona|belino|biga|bocchinara|bocchino|bofilo|boiata|bordello|brinca|bucaiolo|budiùlo|busone|cacca|caciocappella|cadavere|cagare|cagata|cagna|casci|cazzata|cazzimma|cazzo|cesso|cazzone|checca|chiappa|chiavare|chiavata|ciospo|ciucciamiilcazzo|coglione|coglioni|cornuto|cozza|culattina|culattone|culo|ditalino|fava|femminuccia|fica|figa|figliodibuonadonna|figliodiputtana|figone|finocchio|fottere|fottersi|fracicone|fregna|frocio|froscio|goldone|guardone|imbecille|incazzarsi|incoglionirsi|ingoio|leccaculo|lecchino|lofare|loffa|loffare|mannaggia|merda|merdata|merdoso|mignotta|minchia|minchione|mona|monta|montare|mussa|navescuola|nerchia|padulo|palle|palloso|patacca|patonza|pecorina|pesce|picio|pincare|pippa|pinnolone|pipì|pippone|pirla|pisciare|piscio|pisello|pistolotto|pomiciare|pompa|pompino|porca|porcamadonna|porcamiseria|porcaputtana|porco|porcodue|porcozio|potta|puppami|puttana|quaglia|recchione|regina|rincoglionire|rizzarsi|rompiballe|rompipalle|ruffiano|sbattere|sbattersi|sborra|sborrata|sborrone|sbrodolata|scopare|scopata|scorreggiare|sega|slinguare|slinguata|smandrappata|soccia|socmel|sorca|spagnola|spompinare|sticchio|stronza|stronzata|stronzo|succhiami|succhione|sveltina|sverginare|tarzanello|terrone|testadicazzo|tette|tirare|topa|troia|trombare|vacca|vaffanculo|vangare|zinne|ziocantante|zoccola|3p|gスポット|s＆m|sm|sm女王|xx|アジアのかわいい女の子|アスホール|アナリングス|アナル|いたずら|イラマチオ|エクスタシー|エスコート|エッチ|エロティズム|エロティック|オーガズム|オカマ|おしっこ|おしり|オシリ|おしりのあな|おっぱい|オッパイ|オナニー|オマンコ|おもらし|お尻|カーマスートラ|カント|クリトリス|グループ・セックス|グロ|クンニリングス|ゲイ・セックス|ゲイボーイ|ゴールデンシャワー|コカイン|ゴックン|サディズム|しばり|スウィンガー|スカートの中|スカトロ|ストラップオン|ストリップ劇場|スラット|スリット|セクシーな|セクシーな10代|セックス|ソドミー|ちんこ|ディープ・スロート|ディック|ディルド|デートレイプ|デブ|テレフォンセックス|ドッグスタイル|トップレス|なめ|ニガー|ヌード|ネオ・ナチ|ハードコア|パイパン|バイブレーター|バック・スタイル|パンティー|ビッチ|ファック|ファンタジー|フィスト|フェティッシュ|フェラチオ|ふたなり|ぶっかけ|フック|プリンスアルバートピアス|プレイボーイ|ベアバック|ペニス|ペニスバンド|ボーイズラブ|ボールギャグ|ぽっちゃり|ホモ|ポルノ|ポルノグラフィー|ボンテージ|マザー・ファッカー|マスターベーション|まんこ|やおい|やりまん|ラティーナ|ラバー|ランジェリー|レイプ|レズビアン|ローター|ロリータ|淫乱|陰毛|革抑制|騎上位|巨根|巨乳|強姦犯|玉なめ|玉舐め|緊縛|近親相姦|嫌い|後背位|合意の性交|拷問|殺し方|殺人事件|殺人方法|支配|児童性虐待|自己愛性|射精|手コキ|獣姦|女の子|女王様|女子高生|女装|新しいポルノ|人妻|人種|性交|正常位|生殖器|精液|挿入|足フェチ|足を広げる|大陰唇|脱衣|茶色のシャワー|中出し|潮吹き女|潮吹き男性|直腸|剃毛|貞操帯|奴隷|二穴|乳首|尿道プレイ|覗き|売春婦|縛り|噴出|糞|糞尿愛好症|糞便|平手打ち|変態|勃起する|夢精|毛深い|誘惑|幼児性愛者|裸|裸の女性|乱交|両性|両性具有|両刀|輪姦|卍|宦官|肛門|膣|abbuc|aεeṭṭuḍ|aḥeččun|taḥeččunt|axuzziḍ|asxuẓeḍ|qqu|qquɣ|qqiɣ|qqan|qqant|tteqqun|tteqqunt|tteqqun|aqerqur|ajeḥniḍ|awellaq|iwellaqen|iḥeččan|iḥeččunen|uqan|taxna|강간|개새끼|개자식|개좆|개차반|거유|계집년|고자|근친|노모|니기미|뒤질래|딸딸이|때씹|또라이|뙤놈|로리타|망가|몰카|미친|미친새끼|바바리맨|변태|병신|보지|불알|빠구리|사까시|섹스|스와핑|쌍놈|씨발|씨발놈|씨팔|씹|씹물|씹빨|씹새끼|씹알|씹창|씹팔|암캐|애자|야동|야사|야애니|엄창|에로|염병|옘병|유모|육갑|은꼴|자위|자지|잡년|종간나|좆|좆만|죽일년|쥐좆|직촬|짱깨|쪽바리|창녀|포르노|하드코어|호로|화냥년|후레아들|후장|희쭈그리|aardappelsafgieten|achterhetraamzitten|afberen|aflebberen|afrossen|afrukken|aftrekken|afwerkplaats|afzeiken|afzuigen|eenhalvemaneneenpaardekop|anita|asbak|aso|baggerschijten|balen|bedonderen|befborstel|beffen|bekken|belazeren|besodemieterdzijn|besodemieteren|beurt|boemelen|boerelul|boerenpummel|bokkelul|botergeil|broekhoesten|brugpieper|buffelen|buitendepotpiesen|da'sklotenvandebok|deballen|dehoerspelen|dehonduitlaten|dekofferinduiken|del|depijpuitgaan|dombo|draaikont|driehoogachterwonen|drol|drooggeiler|droogkloot|eenbeurtgeven|eennummertjemaken|eenwipmaken|eikel|engerd|flamoes|flikken|flikker|gadverdamme|galbak|gat|gedoogzone|geilneef|gesodemieter|godverdomme|graftak|grasmaaien|gratenkut|greppeldel|griet|hoempert|hoer|hoerenbuurt|hoerenloper|hoerig|hol|hufter|huisdealer|johny|kanen|kettingzeug|klaarkomen|klerebeer|klojo|klooien|klootjesvolk|klootoog|klootzak|kloten|knor|kont|kontneuken|krentekakker|kut|kuttelikkertje|kwakkie|liefdesgrot|lul|lul-de-behanger|lulhannes|lummel|mafketel|matennaaier|matje|mof|muts|naaien|naakt|neuken|neukstier|nicht|oetlul|opgeilen|opkankeren|oprotten|opsodemieteren|opz'nhondjes|opz'nsodemietergeven|opzouten|ouwehoer|ouwehoeren|ouwerukker|paal|paardelul|palen|penoze|piesen|pijpbekkieg|pijpen|pik|pleurislaaier|poep|poepen|poot|portiekslet|pot|potverdorie|publiciteitsgeil|raaskallen|reet|reetridder|reettrappenvoorzijn|remsporen|reutelen|rothoer|rotzak|rukhond|rukken|schatje|schijt|schijten|schoft|schuinsmarcheerder|shit|slempen|slet|sletterig|slikmijnzaad|snol|spuiten|standje|standje-69|stoephoer|stootje|stront|sufferd|tapijtnek|teef|temeier|teringlijer|toeter|tongzoeng|triootjeg|trottoirprostituée|trottoirteef|vergallen|verkloten|verneuken|viespeuk|vingeren|vleesroos|voorjanlul|voorjan-met-de-korte-achternaam|watje|welzijnsmafia|wijf|wippen|wuftje|zaadje|zakkenwasser|zeiken|zeiker|zuigen|zuiplap|asshole|dritt|drittsekk|faen|faenihelvete|fan|fanken|fitte|forbanna|forbannet|forjævlig|fuck|fyfaen|føkk|føkka|føkkings|jævla|jævlig|helvete|helvetet|kuk|kukene|kuker|morraknuller|morrapuler|nigger|pakkis|pikk|pokker|ræva|ræven|satan|shit|sinnsykt|skitt|sotrør|ståpikk|ståpikkene|ståpikker|svartheiteste|burdel|burdelmama|chuj|chujnia|ciota|cipa|cyc|debil|dmuchać|dokurwynędzy|dupa|dupek|duperele|dziwka|fiut|gówno|gównoprawda|huj|hujciwdupę|jajco|jajko|japierdolę|jebać|jebany|kurwa|kurwy|kutafon|kutas|lizaćpałę|obciągaćchuja|obciągaćfiuta|obciągaćloda|pieprzyć|pierdolec|pierdolić|pierdolnąć|pierdolnięty|pierdoła|pierdzieć|pizda|pojeb|pojebany|popierdolony|robicloda|robićloda|ruchać|rzygać|skurwysyn|sraczka|srać|suka|syf|wkurwiać|zajebisty|aborto|amador|ânus|aranha|ariano|balalao|bastardo|bicha|biscate|bissexual|boceta|boob|bosta|brauliodeborracha|bumbum|burro|cabrao|cacete|cagar|camisinha|caralho|cerveja|chochota|chupar|clitoris|cocaína|coito|colhoes|comer|cona|consolo|corno|cu|darorabo|dumraio|esporra|fecal|filhodaputa|foda|foda-se|foder|frangoassado|gozar|grelho|heroína|heterosexual|homemgay|homoerótico|homosexual|inferno|lésbica|lolita|mama|merda|paneleiro|passarumcheque|pau|peidar|pênis|pinto|porra|puta|putaquepariu|putaquetepariu|queca|sacanagem|saco|torneira|transar|vadia|vai-tefoder|vaitomarnocu|veado|vibrador|xana|xochota|bychara|byk|chernozhopyi|dolboy'eb|ebalnik|ebalo|ebalomsch'elkat|gol|mudack|opizdenet|osto'eblo|ostokhuitel'no|ot'ebis|otmudohat|otpizdit|otsosi|padlo|pedik|perdet|petuh|pidargnoinyj|pizda|pizdato|pizdatyi|piz'det|pizdetc|pizdoinakryt'sja|pizd'uk|piz`dyulina|podiku'evo|poeben|po'imat'nakonchik|po'itiposrat|pokhuy|poluchitpizdy|pososimoyukonfetku|prissat|proebat|promudobl'adsksyapizdopro'ebina|propezdoloch|prosrat|raspeezdeyi|raspizdatyi|raz'yebuy|raz'yoba|s'ebat'sya|shalava|styervo|sukinsyn|svoditposrat|svoloch|trakhat'sya|trimandoblydskiypizdoproyob|ubl'yudok|uboy|u'ebitsche|vafl'a|vaflilovit|vpizdu|vyperdysh|vzdrochennyi|yebvas|za'ebat|zaebis|zalupa|zalupat|zasranetc|zassat|zlo'ebuchy|бздёнок|блядки|блядовать|блядство|блядь|бугор|вопизду|встатьраком|выёбываться|гандон|говно|говнюк|голый|датьпизды|дерьмо|дрочить|другойдразнится|ёбарь|ебать|ебать-копать|ебло|ебнуть|ёбтвоюмать|жопа|жополиз|игратьнакожанойфлейте|измудохать|каждыйдрочиткаконхочет|какаяразница|какдвапальцаобоссать|куритемоютрубку|лысоговкулакегонять|малофья|манда|мандавошка|мент|муда|мудило|мудозвон|наебать|наебениться|наебнуться|нафиг|нахуй|нахуювертеть|нахуя|нахуячиться|невебенный|неебет|низахуйсобачу|нихуя|обнаженный|обоссатьсяможно|одинебётся|опесдол|офигеть|охуеть|охуительно|половоесношение|секс|сиськи|спиздить|срать|ссать|траxать|тымневанькуневаляй|фига|хапать|херсней|херсним|хохол|хрен|хуёво|хуёвый|хуемгрушиоколачивать|хуеплет|хуило|хуинейстрадать|хуиня|хуй|хуйнуть|хуйпинать|arsle|brutta|discofitta|draåthelvete|fan|fitta|fittig|förhelvete|helvete|hård|jävlar|knulla|kuk|kuksås|kötthuvud|köttnacke|moona|moonade|moonar|moonat|mutta|nigger|neger|olla|pippa|pitt|prutt|pök|runka|röv|rövhål|rövknulla|satan|skita|skitnerdig|skäggbiff|snedfitta|snefitta|stake|subba|sås|sättapå|tusan|punda|oobhu|thaiyoli|kena|oolu|otha|kandaloli|pochu|koodhi|thaevudiya|oomala|baadu|kunju|poole|thevdiya|gotha|ungathaalaokku|pundarani|pundanakki|savugraaki|kamnaati|sunni|pochandi|othalakka|กระดอ|กระเด้า|กระหรี่|กะปิ|กู|ขี้|ควย|จิ๋ม|จู๋|เจ๊ก|เจี๊ยว|ดอกทอง|ตอแหล|ตูด|น้ําแตก|มึง|แม่ง|เย็ด|รูตูด|ล้างตู้เย็น|ส้นตีน|สัด|เสือก|หญิงชาติชั่ว|หลั่ง|ห่า|หํา|หี|เหี้ย|อมนกเขา|ไอ้ควาย|ghuy'cha'|QI'yaH|Qu'vatlham|amcığa|amcığı|amcığın|amcık|amcıklar|amcıklara|amcıklarda|amcıklardan|amcıkları|amcıkların|amcıkta|amcıktan|amı|amlar|çingene|Çingenede|Çingeneden|Çingeneler|Çingenelerde|Çingenelerden|Çingenelere|Çingeneleri|Çingenelerin|Çingenenin|Çingeneye|Çingeneyi|göt|göte|götler|götlerde|götlerden|götlere|götleri|götlerin|götte|götten|götü|götün|götveren|götverende|götverenden|götverene|götvereni|götverenin|götverenler|götverenlerde|götverenlerden|götverenlere|götverenleri|götverenlerin|kaltağa|kaltağı|kaltağın|kaltak|kaltaklar|kaltaklara|kaltaklarda|kaltaklardan|kaltakları|kaltakların|kaltakta|kaltaktan|orospu|orospuda|orospudan|orospular|orospulara|orospularda|orospulardan|orospuları|orospuların|orospunun|orospuya|orospuyu|otuzbirci|otuzbircide|otuzbirciden|otuzbirciler|otuzbircilerde|otuzbircilerden|otuzbircilere|otuzbircileri|otuzbircilerin|otuzbircinin|otuzbirciye|otuzbirciyi|saksocu|saksocuda|saksocudan|saksocular|saksoculara|saksocularda|saksoculardan|saksocuları|saksocuların|saksocunun|saksocuya|saksocuyu|sıçmak|sik|sike|sikersikmez|siki|sikilirsikilmez|sikin|sikler|siklerde|siklerden|siklere|sikleri|siklerin|sikmek|sikmemek|sikte|sikten|siktir|siktirirsiktirmez|taşağa|taşağı|taşağın|taşak|taşaklar|taşaklara|taşaklarda|taşaklardan|taşakları|taşakların|taşakta|taşaktan|yarağa|yarağı|yarağın|yarak|yaraklar|yaraklara|yaraklarda|yaraklardan|yarakları|yarakların|yarakta|yaraktan|13.|13点|三级片|下三烂|下贱|个老子的|九游|乳|乳交|乳头|乳房|乳波臀浪|交配|仆街|他奶奶|他奶奶的|他奶娘的|他妈|他妈ㄉ王八蛋|他妈地|他妈的|他娘|他马的|你个傻比|你他马的|你全家|你奶奶的|你她马的|你妈|你妈的|你娘|你娘卡好|你娘咧|你它妈的|你它马的|你是鸡|你是鸭|你马的|做爱|傻比|傻逼|册那|军妓|几八|几叭|几巴|几芭|刚度|刚瘪三|包皮|十三点|卖B|卖比|卖淫|卵|卵子|双峰微颤|口交|口肯|叫床|吃屎|后庭|吹箫|塞你公|塞你娘|塞你母|塞你爸|塞你老师|塞你老母|处女|外阴|大卵子|大卵泡|大鸡巴|奶|奶奶的熊|奶子|奸|奸你|她妈地|她妈的|她马的|妈B|妈个B|妈个比|妈个老比|妈妈的|妈比|妈的|妈的B|妈逼|妓|妓女|妓院|妳她妈的|妳妈的|妳娘的|妳老母的|妳马的|姘头|姣西|姦|娘个比|娘的|婊子|婊子养的|嫖娼|嫖客|它妈地|它妈的|密洞|射你|射精|小乳头|小卵子|小卵泡|小瘪三|小肉粒|小骚比|小骚货|小鸡巴|小鸡鸡|屁眼|屁股|屄|屌|巨乳|干x娘|干七八|干你|干你妈|干你娘|干你老母|干你良|干妳妈|干妳娘|干妳老母|干妳马|干您娘|干机掰|干死CS|干死GM|干死你|干死客服|幹|强奸|强奸你|性|性交|性器|性无能|性爱|情色|想上你|懆您妈|懆您娘|懒8|懒八|懒叫|懒教|成人|我操你祖宗十八代|扒光|打炮|打飞机|抽插|招妓|插你|插死你|撒尿|操你|操你全家|操你奶奶|操你妈|操你娘|操你祖宗|操你老妈|操你老母|操妳|操妳全家|操妳妈|操妳娘|操妳祖宗|操机掰|操比|操逼|放荡|日他娘|日你|日你妈|日你老娘|日你老母|日批|月经|机八|机巴|机机歪歪|杂种|浪叫|淫|淫乱|淫妇|淫棍|淫水|淫秽|淫荡|淫西|湿透的内裤|激情|灨你娘|烂货|烂逼|爛|狗屁|狗日|狗狼养的|玉杵|王八蛋|瓜娃子|瓜婆娘|瓜批|瘪三|白烂|白痴|白癡|祖宗|私服|笨蛋|精子|老二|老味|老母|老瘪三|老骚比|老骚货|肉壁|肉棍子|肉棒|肉缝|肏|肛交|肥西|色情|花柳|荡妇|賤|贝肉|贱B|贱人|贱货|贼你妈|赛你老母|赛妳阿母|赣您娘|轮奸|迷药|逼|逼样|野鸡|阳具|阳萎|阴唇|阴户|阴核|阴毛|阴茎|阴道|阴部|雞巴|靠北|靠母|靠爸|靠背|靠腰|驶你公|驶你娘|驶你母|驶你爸|驶你老师|驶你老母|骚比|骚货|骚逼|鬼公|鸡8|鸡八|鸡叭|鸡吧|鸡奸|鸡巴|鸡芭|鸡鸡|龟儿子|龟头|𨳒|陰莖|㞗|尻|𨳊|鳩|𡳞|𨶙|撚|𨳍|柒|閪|仆街|咸家鏟|冚家鏟|咸家伶|冚家拎|笨實|粉腸|屎忽|躝癱|你老闆|你老味|你老母|硬膠)[^!@#$%^&*]*";
    lazy_static! {
        static ref RE_PROFAINITY: Regex =
            Regex::new(PROFAINITY).expect("coudln't setup profainity filter");
    }

    if RE_PROFAINITY.is_match(&target) {
        Err(CredsError::ProfainityError)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profainity_ture1() {
        let illegal = "fuck";
        let illegal2 = "pundapayale";

        let legal = "hey";
        assert_eq!(beep(legal), Ok(()));
        assert_eq!(beep(illegal), Err(CredsError::ProfainityError));
        assert_eq!(beep(illegal2), Err(CredsError::ProfainityError));
    }
}
