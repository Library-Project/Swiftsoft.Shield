## INTERFACE

    public interface ISecurityService<TResult>
        where TResult: class
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        SecurityContract Encrypt(TResult data);
    
        /// <summary>
        /// 
        /// </summary>
        /// <param name="contract"></param>
        /// <returns></returns>
        TResult Decrypt(SecurityContract contract);
    }

## CLASS

    /// <summary>
    /// Service de chiffrement/déchiffrement des payloads.
    /// Chiffrement : AES-256-CBC (confidentialité).
    /// Intégrité   : HMAC-SHA256 (détection de toute modification).
    /// </summary>
    /// <typeparam name="TResult">Type des données à chiffrer/déchiffrer.</typeparam>
    public sealed  class SecurityService<TResult> : ISecurityService<TResult>
        where TResult: class
    {
        #region Properties (Private)

        // Une instance par TResult, créée au premier appel (thread-safe).
        // Elle lit la configuration partagée de SecurityConfig.
        private static readonly Lazy<SecurityService<TResult>> _instance =
            new(() => new SecurityService<TResult>(SecuritySettingsConfig.Settings));

        /// <summary>Instance utilisable sans injection de dépendances.</summary>
        public static ISecurityService<TResult> Instance => _instance.Value;

        // Clé AES de 32 octets (256 bits).
        // Sert à chiffrer ET déchiffrer (chiffrement symétrique).
        private readonly byte[] _key;
    
        // Clé secrète du HMAC. Sert à calculer la "signature" d'intégrité.
        // Différente de _key : on ne réutilise jamais la même clé pour deux usages.
        private readonly byte[] _hmacKey;

        // Réglages appliqués quand Newtonsoft construit un JToken à partir d'un texte JSON : identiques à l'encodage et au décodage.
        private static readonly JsonLoadSettings LoadSettings = new()
        {
            // Les commentaires éventuels dans le JSON sont ignorés (pas d'erreur, pas conservés).
            CommentHandling = CommentHandling.Ignore
        };

        // Réglages appliqués lors de la désérialisation vers un type concret (DTO).
        private static readonly JsonSerializerSettings ReadSettings = new()
        {
            // Une chaîne qui ressemble à une date ("2024-01-05") reste une chaîne.
            // Sans cela, Newtonsoft la convertit en DateTime et la réécrit dans un autre format,
            // ce qui changerait le texte et ferait échouer le HMAC.
            DateParseHandling = DateParseHandling.None,
        
            // Les nombres à virgule sont lus en decimal (précis) plutôt qu'en double (arrondis possibles).
            FloatParseHandling = FloatParseHandling.Decimal
        };

        #endregion
    
        #region Constructors (Public)

        // Utilisé par l'injection de dépendances : délègue au constructeur ci-dessous.
        public SecurityService(IOptions<PayloadSecuritySettings> appSettingsSection) : this(appSettingsSection.Value)
        {
        }
    
        /// <summary>
        /// Le constructeur reçoit la configuration par injection de dépendances.
        /// IOptions&lt;AppSettings&gt; = la section "AppSettings" de appsettings.json, mappée sur une classe C#.
        /// </summary>
        private  SecurityService(PayloadSecuritySettings appPayloadSettings)
        {
            // Les clés sont stockées en Base64 (texte) dans le JSON, car un JSON ne peut pas contenir d'octets bruts.
            // On les convertit en tableaux d'octets une seule fois, ici, plutôt qu'à chaque appel (plus rapide).
            _key = Convert.FromBase64String(appPayloadSettings.AesKey);
            _hmacKey = Convert.FromBase64String(appPayloadSettings.HmacKey);
        }

        #endregion

        #region Methods (Public)
    
        /// <summary>
        /// Chiffre un objet et retourne un SecurityContract.
        /// Flux : objet -> JSON canonique -> enveloppe {Integrity, Data} -> AES -> Base64 -> HMAC.
        /// </summary>
        public SecurityContract Encrypt(TResult data)
        {
            // ÉTAPE 1 : sérialiser les données avec Newtonsoft, puis les mettre sous forme "canonique"
            // (JSON compact, relu avec les mêmes réglages qu'au décodage).
            // Le HMAC interne est calculé sur CETTE chaîne, il doit être strictement identique
            // à l'encodage et au décodage, sinon la vérification échoue.
            var dataJson = Canonicalize(JsonConvert.SerializeObject(data));

            // Enveloppe interne : { "Integrity": "...", "Data": { ... } }
            var envelope = new JObject
            {
                // Signature HMAC des données (vérifiée au déchiffrement).
                ["Integrity"] = ComputeIntegrity(dataJson),

                // Les données, reparsées en JToken pour être insérées comme vrai JSON
                // (et non comme une chaîne avec des guillemets échappés).
                ["Data"] = ParseToken(dataJson)
            };
        
            // Enveloppe en texte JSON compact (Formatting.None = sans espaces ni retours à la ligne).
            var json = envelope.ToString(Formatting.None);

            // ÉTAPE 2 : préparer AES avec un IV aléatoire de 16 octets (non secret, transmis avec les données).
            // "using" libère l'objet automatiquement à la fin de la méthode.
            using var aes = Aes.Create();

            // Donne à AES la clé secrète de 32 octets.
            aes.Key = _key;

            // On génère un IV (vecteur d'initialisation) ALÉATOIRE de 16 octets, à chaque chiffrement.
            // Pourquoi ? Si on chiffrait deux fois le même texte avec la même clé et sans IV aléatoire,
            // on obtiendrait le même résultat, ce qui révèlerait des informations. Avec un IV différent
            // à chaque fois, le même texte donne un résultat différent. L'IV n'est PAS secret :
            // on le transmet avec les données chiffrées.
            aes.GenerateIV();
        
            // Crée l'objet qui effectue le chiffrement avec la clé et l'IV configurés.
            using var encryptor = aes.CreateEncryptor();
        
            // AES travaille sur des octets, pas sur du texte : on convertit le JSON en octets UTF-8.
            var plainBytes = Encoding.UTF8.GetBytes(json);

            // ÉTAPE 3 : chiffrement (AES-CBC, avec padding).
            // TransformFinalBlock traite tous les octets d'un coup (début 0, longueur = tout).
            // Le mode CBC (cipher block chaining) ajoute du "padding" pour compléter le dernier bloc de 16 octets, donc
            // cipherBytes est un peu plus long que plainBytes.
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            // ÉTAPE 4 : assembler le payload
            // Payload final = IV (16 octets) + données chiffrées, en Base64.
            // On met l'IV devant : au déchiffrement, on aura besoin du même IV.
            // Convert.ToBase64String transforme ces octets en texte, pour pouvoir les mettre dans un JSON.
            var payload = Convert.ToBase64String(aes.IV.Concat(cipherBytes).ToArray());

            // ÉTAPE 5 : contrat final renvoyé au client, avec le HMAC du payload chiffré (couche externe).
            return new SecurityContract(
                velocity: 1,                             // numéro de version du protocole (champ libre)
                graduation: plainBytes.Length,           // taille du texte clair avant chiffrement (information)
                integrity: ComputeIntegrity(payload),    // HMAC du payload CHIFFRÉ (couche externe)
                payload: payload);                       // IV + données chiffrées, en Base64
        }
    
        /// <summary>
        /// Déchiffre un SecurityContract et retourne les données en clair.
        /// Flux : HMAC externe -> séparation IV/cipher -> AES -> lecture enveloppe -> HMAC interne -> résultat.
        /// </summary>
        public TResult Decrypt(SecurityContract contract)
        {
            // ÉTAPE 1 : vérifier l'intégrité du payload chiffré AVANT de le déchiffrer (comparaison à temps constant).
            // "expected" = HMAC que NOUS recalculons sur le payload reçu, avec notre clé secrète.
            // Seul quelqu'un qui possède _hmacKey peut produire la bonne valeur.
            var expected = Convert.FromBase64String(ComputeIntegrity(contract.Payload));
        
            // "received" = HMAC envoyé par le client, converti en octets.
            var received = Convert.FromBase64String(contract.Integrity);
        
            // Comparaison "à temps constant" : elle dure toujours le même temps, que les valeurs
            // soient proches ou non. Un simple "==" s'arrête au premier octet différent, ce qui
            // permettrait à un attaquant de deviner la signature en mesurant le temps de réponse.
            if (!CryptographicOperations.FixedTimeEquals(expected, received))
                throw new SecurityException("Intégrité du payload compromise.");

            // ÉTAPE 2 : décoder le payload Base64 en octets : séparer l'IV (16 premiers octets) et les données chiffrées
            var fullBytes = Convert.FromBase64String(contract.Payload);
        
            // Les 16 premiers octets = l'IV (c'est ainsi que Encrypt l'a placé).
            // [..16] = "du début jusqu'à l'index 16 exclu".
            var iv = fullBytes[..16];
        
            // Tout le reste = les données chiffrées. [16..] = "de l'index 16 jusqu'à la fin".
            var cipherBytes = fullBytes[16..];

            // ÉTAPE 3 : déchiffrement AES : préparer AES avec la MÊME clé et le MÊME IV qu'au chiffrement.
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.IV = iv;

            // Crée l'objet qui effectue le déchiffrement.
            using var decryptor = aes.CreateDecryptor();
        
            // Déchiffre tous les octets et retire le padding : on retrouve le JSON de l'enveloppe, en octets.
            var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            // ÉTAPE 4 : lire l'enveloppe SANS la désérialiser vers TResult (pour garder le contenu exact).
            // GetString : octets -> texte. ParseToken : texte -> JToken.
            // "as JObject" : on attend un objet JSON ; sinon on obtient null.
            // "?? throw" : si null, on lève une erreur.
            var root = ParseToken(Encoding.UTF8.GetString(plainBytes)) as JObject
                       ?? throw new SecurityException("Payload illisible.");

            // Les données : erreur si le champ "Data" est absent.
            var dataToken = root["Data"] ?? throw new SecurityException("Payload illisible.");
        
            // Le HMAC interne en texte ("?." évite une exception si le champ est absent).
            var innerIntegrity = root["Integrity"]?.Value<string>();

            // Réécrit Data en JSON compact : forme canonique, identique à celle calculée dans Encrypt.
            var dataJson = dataToken.ToString(Formatting.None);

            // ÉTAPE 5 : intégrité interne, sur les données elles-mêmes.
            // Deuxième vérification, sur les données elles-mêmes.
            // On recalcule le HMAC et on le compare à celui stocké dans l'enveloppe.
            if (ComputeIntegrity(dataJson) != innerIntegrity)
                throw new SecurityException("Données altérées.");

            // ÉTAPE 6 : construire le résultat selon TResult.
            // Si TResult est object, JObject, JToken... : on retourne directement le JToken
            // (un JObject pour un objet JSON). "IsAssignableFrom" = "TResult peut-il recevoir un JToken ?".
            // "(TResult)(object)" : double conversion nécessaire car le compilateur ne connaît pas TResult.
            if (typeof(TResult) == typeof(object) || typeof(JToken).IsAssignableFrom(typeof(TResult)))
                return (TResult)(object)dataToken;

            // Sinon (TResult est un DTO) : désérialisation classique vers ce type.
            // "?? throw" : erreur si le résultat est null.
            return JsonConvert.DeserializeObject<TResult>(dataJson, ReadSettings)
                   ?? throw new SecurityException("Payload illisible.");
        }
    
        #endregion

        #region Methods (Private)

        /// <summary>
        /// Transforme un texte JSON en JToken avec des réglages fixes (les mêmes partout).
        /// </summary>
        private static JToken ParseToken(string json)
        {
            // StringReader : lit le texte comme un flux de caractères.
            using var stringReader = new StringReader(json);

            // JsonTextReader : lecteur JSON de Newtonsoft. C'est lui qui interprète le texte,
            // donc c'est ici qu'on règle la lecture des dates et des décimaux.
            using var reader = new JsonTextReader(stringReader)
            {
                // Les chaînes ressemblant à des dates restent des chaînes.
                DateParseHandling = DateParseHandling.None,
            
                // Les nombres à virgule sont lus en decimal (précision préservée).
                FloatParseHandling = FloatParseHandling.Decimal
            };
        
            // Construit l'arbre JSON (JToken) avec ces réglages.
            return JToken.Load(reader, LoadSettings);
        }

        /// <summary>
        /// JSON -> arbre (JToken) -> JSON compact : le même contenu donne toujours exactement le même texte.
        /// </summary>
        private static string Canonicalize(string json)
            => ParseToken(json).ToString(Formatting.None);

        /// <summary>
        /// Calcule la signature HMAC-SHA256 d'un texte, retournée en Base64.
        /// </summary>
        private string ComputeIntegrity(string data)
        {
            // HMAC-SHA256 = empreinte (hash) SHA-256 calculée AVEC une clé secrète.
            // Un hash simple pourrait être recalculé par n'importe qui après modification des données ;
            // un HMAC ne peut l'être que par quelqu'un qui connaît _hmacKey.
            using var hmac = new HMACSHA256(_hmacKey);
        
            // Convertit le texte en octets, puis calcule l'empreinte (toujours 32 octets,
            // quelle que soit la taille de l'entrée).
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));

            // Convertit les 32 octets en texte Base64 (de 44 caractères) pour le transporter en JSON.
            return Convert.ToBase64String(hash);
        }

        #endregion
    }