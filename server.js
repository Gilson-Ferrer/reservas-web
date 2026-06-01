require('dotenv').config();
const fastify = require('fastify')({ logger: false, trustProxy: true });
const cors = require('@fastify/cors');
const oracledb = require('oracledb');
const rateLimit = require('@fastify/rate-limit');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('@fastify/helmet');

const JWT_SECRET = process.env.JWT_SECRET; 
const saltRounds = 10;

// Configurações do Driver Oracle
oracledb.thin = true;
oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT; 

// Pool de conexão / Helper
async function getDbConnection() {
  return await oracledb.getConnection({
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    connectionString: process.env.DB_CONNECTION_STRING.trim()
  });
}

// Middleware de Autenticação (JWT)
async function validarToken(request, reply) {
    try {
        const authHeader = request.headers.authorization;
        const token = authHeader ? authHeader.split(' ')[1] : null;
        
        if (!token) throw new Error("Acesso negado.");
        
        const decoded = jwt.verify(token, JWT_SECRET);
        request.user = decoded; // Contém userId, email, nome e UNIDADE_ID
    } catch (err) {
        return reply.status(401).send({ success: false, message: "Sessão inválida ou expirada." });
    }
}

// Hook de Proteção da Nuvem (Cloudflare + Render Isolation)
fastify.addHook('onRequest', async (request, reply) => {
    if (request.headers['user-agent']?.includes('Render')) return; 

    if (process.env.NODE_ENV === 'production') {
        const host = request.headers.host;
        const cfIp = request.headers['cf-connecting-ip'];

        if (!cfIp || host.includes('onrender.com')) {
            console.warn(`[BLOQUEIO] Acesso indevido via Host: ${host}`);
            return reply.status(403).send({ 
                success: false, 
                message: "Acesso proibido. Utilize o domínio oficial." 
            });
        }
    }
});

// Segurança e Limitação de Requisições
fastify.register(rateLimit, {
  max: 20, // Um pouco maior para acomodar requisições dinâmicas de horários
  timeWindow: '1 minute',
  errorResponseBuilder: () => ({ success: false, message: 'Muitas requisições. Aguarde um momento.' })
});

fastify.register(helmet);

fastify.register(cors, { 
  origin: ["*"], // Ajuste para a URL final do seu GitHub Pages / Render Static
  methods: ["POST", "GET", "PUT", "DELETE", "OPTIONS"]
});

// Endpoint de Status
fastify.get('/', async () => ({ status: 'online', service: 'SIA-ESTACIO-API' }));

/* ==========================================================================
   📌 ROTA 1: LOGIN (Sem MFA, Isolado por Unidade Lógica)
   ========================================================================== */
fastify.post('/api/auth/login', async (request, reply) => {
    const { email, senha } = request.body;
    let connection;

    console.log(`[DEBUG SIA] E-mail recebido do front: "${email}"`);
    console.log(`[DEBUG SIA] Senha recebida do front: "${senha}"`);

    try {
        connection = await getDbConnection();
        
        // Trazemos o UNIDADE_ID e a ROLE para isolamento lógico
        const sql = `SELECT USUARIO_ID, UNIDADE_ID, NOME, SENHA_HASH, ROLE 
                     FROM SISRESERVA_USUARIOS 
                     WHERE EMAIL = :email`;
                     
        const result = await connection.execute(sql, { email });

        console.log(`[DEBUG SIA] Linhas retornadas do banco Oracle: ${result.rows.length}`);

        if (result.rows.length === 0) {
            return reply.status(401).send({ success: false, message: "Credenciais inválidas." });
        }
        
        const user = result.rows[0];

        const senhaValida = await bcrypt.compare(senha, user.SENHA_HASH || '');
        
        
        console.log(`[DEBUG SIA] Estrutura do objeto 'user' vindo do banco:`, JSON.stringify(user));
        console.log(`[DEBUG SIA] Hash que o Node vai ler: "${user.SENHA_HASH}"`);
        // 🔴 ADICIONE ESTE LOG (Queremos ver se a comparação da senha bateu)
        console.log(`[DEBUG SIA] A senha digitada confere com o Hash? ${senhaValida}`);
        
        if (!senhaValida) {
            return reply.status(401).send({ success: false, message: "Credenciais inválidas." });
        }

        // Token JWT assinado carregando o escopo da unidade do usuário
        const token = jwt.sign(
            { 
                userId: user.USUARIO_ID, 
                unidadeId: user.UNIDADE_ID,
                email: email, 
                nome: user.NOME,
                role: user.ROLE
            }, 
            JWT_SECRET, 
            { expiresIn: '2h' } 
        );

        return {
            success: true,
            token: token,
            user: { nome: user.NOME, role: user.ROLE }
        };

    } catch (err) {
        console.error("Erro no Login:", err);
        return reply.status(500).send({ success: false, message: "Erro interno na autenticação." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 2: TROCA DE SENHA SPONTÂNEA/OBRIGATÓRIA
   ========================================================================== */
fastify.post('/api/user/change-password', { preHandler: [validarToken] }, async (request, reply) => {
    const email = request.user.email; 
    const { novaSenha } = request.body; 
    
    if (!novaSenha || novaSenha.length < 8) {
        return reply.status(400).send({ success: false, message: "A senha deve conter no mínimo 8 caracteres." });
    }

    let connection;
    try {
        connection = await getDbConnection();
        const novaSenhaHasheada = await bcrypt.hash(novaSenha, saltRounds);

        await connection.execute(
            `UPDATE SISRESERVA_USUARIOS SET SENHA_HASH = :senha WHERE EMAIL = :email`,
            { senha: novaSenhaHasheada, email },
            { autoCommit: true }
        );

        return { success: true, message: "Senha alterada com sucesso!" };
    } catch (err) {
        return reply.status(500).send({ success: false, message: "Erro ao atualizar senha." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 3: CONSULTAR HORÁRIOS JÁ OCUPADOS (Para exibição no painel)
   ========================================================================== */
fastify.get('/api/agendamentos/disponibilidade', { preHandler: [validarToken] }, async (request, reply) => {
    const { lab, data } = request.query;
    
    
    // CORREÇÃO: Garante a captura independente da caixa do JWT
    const unidadeId = request.user.unidadeId || request.user.UNIDADE_ID; 

    // LOG DE RASTREIO NO TERMINAL
    console.log(`[DEBUG DASH] Professor consultando: Lab="${lab}" | Data="${data}" | Unidade=${unidadeId}`);
    
    
    if (!lab || !data) {
        return reply.status(400).send({ success: false, message: "Parâmetros 'lab' e 'data' são obrigatórios." });
    }

    let connection;
    try {
        connection = await getDbConnection();

        // Query cirúrgica que traz as ocupações ordenadas, filtrando estritamente pela unidade do usuário
        const sql = `
            SELECT a.AGENDAMENTO_ID, a.HORARIO_INICIO, a.HORARIO_FIM, u.NOME as PROFESSOR
            FROM SISRESERVA_AGENDAMENTOS a
            INNER JOIN SISRESERVA_USUARIOS u ON a.USUARIO_ID = u.USUARIO_ID
            WHERE a.LABORATORIO_NOME = :lab 
              AND a.DATA_AGENDAMENTO = TO_DATE(:data, 'YYYY-MM-DD')
              AND a.UNIDADE_ID = :unidadeId
            ORDER BY a.HORARIO_INICIO ASC
        `;

        const result = await connection.execute(sql, { lab, data, unidadeId });

        // Mapeia os retornos limpando os formatos de data/hora para o front-end
        const ocupacoes = result.rows.map(row => ({
            id: row.AGENDAMENTO_ID,
            inicio: row.HORARIO_INICIO,
            fim: row.HORARIO_FIM,
            professor: row.PROFESSOR
        }));

        return { success: true, ocupacoes };

    } catch (err) {
        console.error("Erro ao checar horários:", err.message);
        return reply.status(500).send({ success: false, message: "Erro ao consultar o banco de dados." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 4: REALIZAR NOVO AGENDAMENTO (Com validação estrita de colisão)
   ========================================================================== */
fastify.post('/api/agendamentos/reservar', { preHandler: [validarToken] }, async (request, reply) => {
    const { lab, data, inicio, fim } = request.body;
    
    // CORREÇÃO: Garante a captura segura das credenciais do token
    const userId = request.user.userId || request.user.USUARIO_ID;
    const unidadeId = request.user.unidadeId || request.user.UNIDADE_ID;

    console.log(`[DEBUG DASH] Tentativa de Reserva: Lab="${lab}" | Professor ID=${userId} | Unidade=${unidadeId}`);

    // 1. Validação básica de payload
    if (!lab || !data || !inicio || !fim) {
        return reply.status(400).send({ success: false, message: "Todos os campos são obrigatórios." });
    }

    const instanteAtual = new Date();
    const instanteReserva = new Date(`${data}T${inicio}:00`);

    if (instanteReserva < instanteAtual) {
        console.warn(`[BLOQUEIO RETROATIVO] Tentativa de agendamento passado negada para o User ID: ${userId}`);
        return reply.status(400).send({ 
            success: false, 
            message: "Erro: Não é permitido agendar laboratórios para horários retroativos." 
        });
    }

    const limiteFuturo = new Date();
    limiteFuturo.setDate(limiteFuturo.getDate() + 180); // Calcula exatamente a data de hoje + 180 dias

    if (instanteReserva > limiteFuturo) {
        console.warn(`[BLOQUEIO ANTECEDÊNCIA] Tentativa de reserva acima do limite de 180 dias pelo User ID: ${userId}`);
        return reply.status(400).send({ 
            success: false, 
            message: "Operação Recusada! Os agendamentos só podem ser realizados com no máximo 180 dias (6 meses) de antecedência." 
        });
    }

    // 2. Regra de Escopo: Restrição de funcionamento (07:00 às 23:00)
    if (inicio < "07:00" || fim > "23:00" || inicio >= fim) {
        return reply.status(400).send({ success: false, message: "Horário fora da janela permitida (07:00 às 23:00)." });
    }

    let connection;
    try {
        connection = await getDbConnection();

        // 3. Regra de Ouro: Query matemática de colisão de horários (Evita Double-Booking)
        const sqlConflito = `
            SELECT COUNT(*) AS CONFLITOS 
            FROM SISRESERVA_AGENDAMENTOS
            WHERE LABORATORIO_NOME = :lab
              AND DATA_AGENDAMENTO = TO_DATE(:data, 'YYYY-MM-DD')
              AND UNIDADE_ID = :unidadeId
              AND (:inicio < HORARIO_FIM AND :fim > HORARIO_INICIO)
        `;

        const checkResult = await connection.execute(sqlConflito, { lab, data, unidadeId, inicio, fim });
        
        if (checkResult.rows[0].CONFLITOS > 0) {
            return reply.status(409).send({ 
                success: false, 
                message: "Conflito detectado! Este espaço já foi reservado por outro professor neste horário." 
            });
        }

        // 4. Inserção Limpa com ISOLAÇÃO LÓGICA por Unidade
        const sqlInsert = `
            INSERT INTO SISRESERVA_AGENDAMENTOS 
            (UNIDADE_ID, USUARIO_ID, LABORATORIO_NOME, DATA_AGENDAMENTO, HORARIO_INICIO, HORARIO_FIM)
            VALUES (:unidadeId, :userId, :lab, TO_DATE(:data, 'YYYY-MM-DD'), :inicio, :fim)
        `;

        await connection.execute(sqlInsert, { unidadeId, userId, lab, data, inicio, fim }, { autoCommit: true });

        return { success: true, message: "Agendamento semestral realizado com sucesso!" };

    } catch (err) {
        console.error("Erro ao agendar:", err.message);
        return reply.status(500).send({ success: false, message: "Erro interno ao processar a reserva." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 5: CANCELAR AGENDAMENTO ATIVO (TRAVA DE 1 HORA ANTES)
   ========================================================================== */
fastify.delete('/api/agendamentos/cancelar/:id', { preHandler: [validarToken] }, async (request, reply) => {
    const { id } = request.params;
    const { userId, role, unidadeId } = request.user;

    let connection;
    try {
        connection = await getDbConnection();
        const idNumerico = Number(id);

        // 1. Busca a data e hora do agendamento para checar a antecedência
        const sqlCheck = `SELECT TO_CHAR(DATA_AGENDAMENTO, 'YYYY-MM-DD') AS DATA, HORARIO_INICIO 
                          FROM SISRESERVA_AGENDAMENTOS 
                          WHERE AGENDAMENTO_ID = :idNumerico AND UNIDADE_ID = :unidadeId`;
        
        const resCheck = await connection.execute(sqlCheck, { idNumerico, unidadeId });

        if (resCheck.rows.length === 0) {
            return reply.status(404).send({ success: false, message: "Agendamento não localizado." });
        }

        const agendamento = resCheck.rows[0];
        
        // 2. Monta o objeto Date do agendamento e o momento atual do servidor
        const dataHoraAgendamento = new Date(`${agendamento.DATA}T${agendamento.HORARIO_INICIO}:00`);
        const agora = new Date();

        // 3. Calcula a diferença em milissegundos e converte para horas
        const diferencaHoras = (dataHoraAgendamento - agora) / (1000 * 60 * 60);

        // Se faltar menos de 1 hora (e o solicitante não for o ADMIN), bloqueia o cancelamento
        if (diferencaHoras < 1 && role !== 'ADMIN') {
            return reply.status(403).send({ 
                success: false, 
                message: "Bloqueado: O cancelamento só é permitido com antecedência mínima de 1 hora do horário reservado." 
            });
        }

        // 4. Executa a exclusão se passar na trava cronológica
        const sqlDelete = `DELETE FROM SISRESERVA_AGENDAMENTOS 
                           WHERE AGENDAMENTO_ID = :idNumerico 
                             AND UNIDADE_ID = :unidadeId 
                             AND (USUARIO_ID = :userId OR :role = 'ADMIN')`;

        const result = await connection.execute(sqlDelete, { idNumerico, unidadeId, userId, role }, { autoCommit: true });

        if (result.rowsAffected === 0) {
            return reply.status(403).send({ success: false, message: "Ação não autorizada para este usuário." });
        }

        return { success: true, message: "Agendamento cancelado e liberação concluída!" };
    } catch (err) {
        console.error("Erro ao cancelar:", err.message);
        return reply.status(500).send({ success: false, message: "Erro interno ao processar cancelamento." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 6: LISTAR HISTÓRICO DE RESERVAS ATIVAS (FILTRANDO O PASSADO)
   ========================================================================== */
fastify.get('/api/agendamentos/meus', { preHandler: [validarToken] }, async (request, reply) => {
    const { userId, unidadeId } = request.user;

    let connection;
    try {
        connection = await getDbConnection();

        // FILTRO CRUCIAL: DATA_AGENDAMENTO >= TRUNC(SYSDATE) oculta os dias anteriores
        const sql = `
            SELECT AGENDAMENTO_ID, LABORATORIO_NOME, TO_CHAR(DATA_AGENDAMENTO, 'YYYY-MM-DD') AS DATA_RESERVA, HORARIO_INICIO, HORARIO_FIM
            FROM SISRESERVA_AGENDAMENTOS
            WHERE USUARIO_ID = :userId 
              AND UNIDADE_ID = :unidadeId
              AND DATA_AGENDAMENTO >= TRUNC(SYSDATE)
            ORDER BY DATA_AGENDAMENTO ASC, HORARIO_INICIO ASC
        `;

        const result = await connection.execute(sql, { userId, unidadeId });

        const reservas = result.rows.map(row => ({
            id: row.AGENDAMENTO_ID,
            lab: row.LABORATORIO_NOME,
            data: row.DATA_RESERVA,
            inicio: row.HORARIO_INICIO,
            fim: row.HORARIO_FIM
        }));

        return { success: true, reservas };
    } catch (err) {
        console.error("Erro ao listar agendamentos do usuário:", err.message);
        return reply.status(500).send({ success: false, message: "Erro ao consultar reservas." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 7: LISTAR LABORATÓRIOS DA UNIDADE ATIVA (GET)
   ========================================================================== */
fastify.get('/api/laboratorios', { preHandler: [validarToken] }, async (request, reply) => {
    const unidadeId = request.user.unidadeId || request.user.UNIDADE_ID;

    let connection;
    try {
        connection = await getDbConnection();

        // Traz apenas os laboratórios ativos da unidade lógica do usuário logado
        const sql = `SELECT LABORATORIO_ID, NOME_LABORATORIO 
                     FROM SISRESERVA_LABORATORIOS 
                     WHERE UNIDADE_ID = :unidadeId AND STATUS = 'ATIVO'
                     ORDER BY LOWER(NOME_LABORATORIO) ASC`;

        const result = await connection.execute(sql, { unidadeId });

        const labs = result.rows.map(row => ({
            id: row.LABORATORIO_ID,
            nome: row.NOME_LABORATORIO
        }));

        return { success: true, laboratorios: labs };
    } catch (err) {
        console.error("Erro ao buscar laboratórios:", err.message);
        return reply.status(500).send({ success: false, message: "Erro ao consultar a lista de espaços." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 8: ADICIONAR NOVO LABORATÓRIO (POST - EXCLUSIVO ADMIN)
   ========================================================================== */
fastify.post('/api/laboratorios/adicionar', { preHandler: [validarToken] }, async (request, reply) => {
    const { nomeLab } = request.body;
    const { role } = request.user;
    const unidadeId = request.user.unidadeId || request.user.UNIDADE_ID;

    // Trava de segurança no servidor: Se não for ADMIN, barra a gravação
    if (role !== 'ADMIN') {
        return reply.status(403).send({ success: false, message: "Acesso negado. Operação exclusiva para administradores." });
    }

    if (!nomeLab || nomeLab.trim() === "") {
        return reply.status(400).send({ success: false, message: "O nome do laboratório é obrigatório." });
    }

    let connection;
    try {
        connection = await getDbConnection();

        const sql = `INSERT INTO SISRESERVA_LABORATORIOS (UNIDADE_ID, NOME_LABORATORIO) 
                     VALUES (:unidadeId, :nomeLab)`;

        await connection.execute(sql, { unidadeId, nomeLab: nomeLab.trim() }, { autoCommit: true });

        return { success: true, message: "Novo laboratório integrado e registrado com sucesso!" };
    } catch (err) {
        console.error("Erro ao inserir laboratório:", err.message);
        return reply.status(500).send({ success: false, message: "Erro interno ao salvar o espaço no banco." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 9: DESATIVAR/REMOVER LABORATÓRIO (PUT - EXCLUSIVO ADMIN)
   ========================================================================== */
fastify.put('/api/laboratorios/remover/:id', { preHandler: [validarToken] }, async (request, reply) => {
    const { id } = request.params;
    const { role } = request.user;
    const unidadeId = request.user.unidadeId || request.user.UNIDADE_ID;

    if (role !== 'ADMIN') {
        return reply.status(403).send({ success: false, message: "Acesso negado." });
    }

    let connection;
    try {
        connection = await getDbConnection();
        const idNumerico = Number(id);

        // Fazemos uma remoção lógica mudando o status para 'INATIVO' para preservar o histórico de agendamentos antigos
        const sql = `UPDATE SISRESERVA_LABORATORIOS 
                     SET STATUS = 'INATIVO' 
                     WHERE LABORATORIO_ID = :idNumerico AND UNIDADE_ID = :unidadeId`;

        const result = await connection.execute(sql, { idNumerico, unidadeId }, { autoCommit: true });

        if (result.rowsAffected === 0) {
            return reply.status(404).send({ success: false, message: "Espaço não encontrado." });
        }

        return { success: true, message: "Laboratório desativado com sucesso!" };
    } catch (err) {
        console.error(err);
        return reply.status(500).send({ success: false, message: "Erro ao remover espaço." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 10: RELATÓRIO DE RESERVAS POR DATA CUSTOMIZADA (GET - ADMIN)
   ========================================================================== */
fastify.get('/api/admin/agendamentos-hoje', { preHandler: [validarToken] }, async (request, reply) => {
    const { role } = request.user;
    const { data } = request.query; // Captura a data enviada pelo painel administrativo
    const unidadeId = request.user.unidadeId || request.user.UNIDADE_ID;

    if (role !== 'ADMIN') {
        return reply.status(403).send({ success: false, message: "Acesso negado." });
    }

    let connection;
    try {
        connection = await getDbConnection();

        // Se o admin não passar nenhuma data, o sistema usa por padrão a data de HOJE (TRUNC(SYSDATE))
        const sql = `
            SELECT a.LABORATORIO_NOME, u.NOME AS PROFESSOR, a.HORARIO_INICIO, a.HORARIO_FIM
            FROM SISRESERVA_AGENDAMENTOS a
            INNER JOIN SISRESERVA_USUARIOS u ON a.USUARIO_ID = u.USUARIO_ID
            WHERE a.UNIDADE_ID = :unidadeId 
              AND a.DATA_AGENDAMENTO = NVL(TO_DATE(:data, 'YYYY-MM-DD'), TRUNC(SYSDATE))
            ORDER BY a.LABORATORIO_NOME ASC, a.HORARIO_INICIO ASC
        `;

        const result = await connection.execute(sql, { unidadeId, data: data || null });

        const relatorio = result.rows.map(row => ({
            lab: row.LABORATORIO_NOME,
            prof: row.PROFESSOR,
            hora: `${row.HORARIO_INICIO} às ${row.HORARIO_FIM}`
        }));

        return { success: true, agendamentos: relatorio };
    } catch (err) {
        console.error("Erro no relatório do Admin:", err.message);
        return reply.status(500).send({ success: false, message: "Erro ao compilar agenda." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 11: BALANÇO DE UTILIZAÇÃO REAL POR INTERVALO DE DATAS (GET - ADMIN)
   ========================================================================== */
fastify.get('/api/admin/balanco-uso', { preHandler: [validarToken] }, async (request, reply) => {
    const { role } = request.user;
    const { inicio, fim } = request.query; // Captura o intervalo de datas enviado pelo front
    const unidadeId = request.user.unidadeId || request.user.UNIDADE_ID;

    if (role !== 'ADMIN') {
        return reply.status(403).send({ success: false, message: "Acesso negado." });
    }

    let connection;
    try {
        connection = await getDbConnection();

        // Se o operador não passar datas, o Oracle filtra por padrão os últimos 30 dias:
        // Data início: Hoje menos 30 dias | Data fim: Hoje às 23:59:59
        const sql = `
            SELECT 
                l.NOME_LABORATORIO,
                NVL(ROUND((COUNT(a.AGENDAMENTO_ID) / NULLIF(SUM(COUNT(a.AGENDAMENTO_ID)) OVER(), 0)) * 100), 0) AS PERCENTUAL
            FROM SISRESERVA_LABORATORIOS l
            LEFT JOIN SISRESERVA_AGENDAMENTOS a 
                ON l.NOME_LABORATORIO = a.LABORATORIO_NOME 
               AND a.UNIDADE_ID = :unidadeId
               AND a.DATA_AGENDAMENTO BETWEEN NVL(TO_DATE(:inicio, 'YYYY-MM-DD'), TRUNC(SYSDATE) - 30) 
                                         AND NVL(TO_DATE(:fim, 'YYYY-MM-DD'), TRUNC(SYSDATE) + 0.99999)
            WHERE l.UNIDADE_ID = :unidadeId AND l.STATUS = 'ATIVO'
            GROUP BY l.NOME_LABORATORIO
            ORDER BY LOWER(l.NOME_LABORATORIO) ASC
        `;

        const result = await connection.execute(sql, { 
            unidadeId, 
            inicio: inicio || null, 
            fim: fim || null 
        });

        const dadosBalanco = result.rows.map(row => ({
            nome: row.NOME_LABORATORIO,
            percentual: row.PERCENTUAL
        }));

        return { success: true, balanco: dadosBalanco };
    } catch (err) {
        console.error("Erro ao calcular balanço dinâmico:", err.message);
        return reply.status(500).send({ success: false, message: "Erro interno ao computar métricas." });
    } finally {
        if (connection) await connection.close();
    }
});

/* ==========================================================================
   📌 ROTA 12: CADASTRAR NOVO DOCENTE (POST - EXCLUSIVO ADMIN)
   ========================================================================== */
fastify.post('/api/admin/docentes/cadastrar', { preHandler: [validarToken] }, async (request, reply) => {
    const { nome, email, senha } = request.body;
    const { role } = request.user;
    const unidadeId = request.user.unidadeId || request.user.UNIDADE_ID;

    // 1. Trava estrita de Perfil
    if (role !== 'ADMIN') {
        return reply.status(403).send({ success: false, message: "Acesso negado. Função exclusiva do Administrador." });
    }

    // 2. Validação de Payload e Segurança Cronológica da Senha
    if (!nome || !email || !senha) {
        return reply.status(400).send({ success: false, message: "Todos os campos (Nome, E-mail e Senha) são obrigatórios." });
    }

    if (senha.length < 8) {
        return reply.status(400).send({ success: false, message: "A senha de acesso precisa ter no mínimo 8 caracteres." });
    }

    let connection;
    try {
        connection = await getDbConnection();

        // 3. Regra de Negócio: Verifica se o e-mail institucional já não está registrado na base
        const sqlCheck = `SELECT COUNT(*) AS QTD FROM SISRESERVA_USUARIOS WHERE LOWER(EMAIL) = LOWER(:email)`;
        const checkResult = await connection.execute(sqlCheck, { email: email.trim() });

        if (checkResult.rows[0].QTD > 0) {
            return reply.status(409).send({ success: false, message: "Conflito: Este e-mail institucional já está cadastrado no sistema." });
        }

        // 4. Gera a criptografia Hashing Bcrypt com fator de custo 10
        const hashGerado = await bcrypt.hash(senha, saltRounds);

        // 5. Persiste fisicamente com o papel (Role) padrão de PROFESSOR e Status ATIVO
        const sqlInsert = `
            INSERT INTO SISRESERVA_USUARIOS (UNIDADE_ID, NOME, EMAIL, SENHA_HASH, ROLE, STATUS)
            VALUES (:unidadeId, :nome, LOWER(:email), :hashGerado, 'PROFESSOR', 'ATIVO')
        `;

        await connection.execute(sqlInsert, {
            unidadeId,
            nome: nome.trim(),
            email: email.trim(),
            hashGerado
        }, { autoCommit: true });

        return { success: true, message: `Professor(a) ${nome} cadastrado com sucesso!` };

    } catch (err) {
        console.error("Erro ao registrar docente:", err.message);
        return reply.status(500).send({ success: false, message: "Erro interno do servidor ao salvar o registro." });
    } finally {
        if (connection) await connection.close();
    }
});

// O START DEVE FICAR SEMPRE POR ÚLTIMO, DEPOIS DE TODAS AS ROTAS DECLARADAS!
const start = async () => {
  try {
    const port = process.env.PORT || 10000;
    await fastify.listen({ port: port, host: '0.0.0.0' });
    console.log(`Backend SisReserva Ativo na porta ${port}`);
  } catch (err) {
    console.error("Erro ao iniciar o servidor:", err);
    process.exit(1);
  }
};

start();