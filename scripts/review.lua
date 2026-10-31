-- Review UI for scripts/review.sh.
--
-- Layout: one tab, old | new | REVIEW.md. The two left windows hold the native
-- diff of one reviewed file at a time, the right window holds the notes buffer
-- that the agent reads back after nvim exits.
--
-- No plugin dependencies: only diffthis, splits and a few commands.

local state = {
    ws = nil,
    files = {},
    index = 1,
    old_win = nil,
    new_win = nil,
    review_win = nil,
    review_buf = nil,
}

local function trim(text)
    return (text:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function read_json(path)
    local fd = io.open(path, "r")
    if not fd then
        error("review: cannot open " .. path)
    end
    local body = fd:read("*a")
    fd:close()
    local ok, data = pcall(vim.json.decode, body)
    if not ok then
        error("review: malformed manifest " .. path)
    end
    return data
end

local function review_path()
    return state.ws .. "/REVIEW.md"
end

local function open_code(index)
    local file = state.files[index]
    if not file then
        return
    end
    state.index = index

    vim.api.nvim_set_current_win(state.old_win)
    vim.cmd("silent edit! " .. vim.fn.fnameescape(file.old))
    vim.cmd("diffthis")

    vim.api.nvim_set_current_win(state.new_win)
    vim.cmd("silent edit! " .. vim.fn.fnameescape(file.path))
    vim.cmd("diffthis")
    vim.cmd("silent diffupdate")

    local hunk = file.hunks[1]
    local line = hunk and hunk.start or 1
    local last = vim.api.nvim_buf_line_count(vim.api.nvim_win_get_buf(state.new_win))
    if line > last then
        line = last
    end
    vim.api.nvim_win_set_cursor(state.new_win, { line, 0 })
    vim.cmd("normal! zz")
end

local function jump_from_anchor()
    local lines = vim.api.nvim_buf_get_lines(0, 0, -1, false)
    local row = vim.api.nvim_win_get_cursor(0)[1]
    local path, target

    for i = row, 1, -1 do
        if not target then
            local start = lines[i]:match("^###%s+hunk%s+(%d+)")
            if start then
                target = tonumber(start)
            end
        end
        local heading = lines[i]:match("^##%s+(.+)$")
        if heading then
            path = trim(heading)
            break
        end
    end

    if not path then
        return
    end

    for index, file in ipairs(state.files) do
        if file.rel == path then
            open_code(index)
            local line = target or 1
            local last = vim.api.nvim_buf_line_count(vim.api.nvim_win_get_buf(state.new_win))
            if line > last then
                line = last
            end
            vim.api.nvim_win_set_cursor(state.new_win, { line, 0 })
            vim.cmd("normal! zz")
            vim.api.nvim_set_current_win(state.new_win)
            return
        end
    end
end

local function is_note(line)
    local text = trim(line)
    return text ~= "" and not text:match("^<!--") and text ~= "-->"
end

local function has_note(lines)
    for _, line in ipairs(lines) do
        if is_note(line) then
            return true
        end
    end
    return false
end

local function push_body(out, body)
    local last = #body
    while last > 0 and trim(body[last]) == "" do
        last = last - 1
    end
    for i = 1, last do
        out[#out + 1] = body[i]
    end
end

local function collect_notes(lines)
    local sections = {}
    local current

    for _, line in ipairs(lines) do
        if line:match("^###%s") then
            if current then
                current.hunks[#current.hunks + 1] = { header = line, body = {} }
            end
        elseif line:match("^##%s") then
            current = { header = line, body = {}, hunks = {} }
            sections[#sections + 1] = current
        elseif current then
            local target = current.hunks[#current.hunks]
            target = target and target or current
            target.body[#target.body + 1] = line
        end
    end

    local out = {}
    for _, section in ipairs(sections) do
        local block = {}
        if has_note(section.body) then
            push_body(block, section.body)
            block[#block + 1] = ""
        end
        for _, hunk in ipairs(section.hunks) do
            if has_note(hunk.body) then
                block[#block + 1] = hunk.header
                block[#block + 1] = ""
                push_body(block, hunk.body)
                block[#block + 1] = ""
            end
        end
        if #block > 0 then
            out[#out + 1] = section.header
            out[#out + 1] = ""
            for _, line in ipairs(block) do
                out[#out + 1] = line
            end
            out[#out + 1] = ""
        end
    end

    return out
end

local function write_comments()
    if not state.review_buf or not vim.api.nvim_buf_is_valid(state.review_buf) then
        return
    end
    local lines = vim.api.nvim_buf_get_lines(state.review_buf, 0, -1, false)
    local notes = collect_notes(lines)
    local path = state.ws .. "/comments.md"
    local fd = io.open(path, "w")
    if not fd then
        return
    end
    if #notes > 0 then
        fd:write(table.concat(notes, "\n"), "\n")
    end
    fd:close()
end

local function save_review()
    if state.review_buf and vim.api.nvim_buf_is_valid(state.review_buf) then
        vim.api.nvim_buf_call(state.review_buf, function()
            vim.cmd("silent! write")
        end)
    end
end

local function step(delta)
    local count = #state.files
    if count == 0 then
        return
    end
    local index = (state.index - 1 + delta) % count + 1
    open_code(index)
    vim.api.nvim_set_current_win(state.new_win)
end

local function setup_keys(review_buf)
    local options = { buffer = review_buf, silent = true, nowait = true }
    vim.keymap.set("n", "<CR>", jump_from_anchor, options)
    vim.keymap.set("n", "]f", function()
        step(1)
    end, options)
    vim.keymap.set("n", "[f", function()
        step(-1)
    end, options)

    local code = { silent = true, nowait = true }
    vim.keymap.set("n", "]f", function()
        step(1)
    end, code)
    vim.keymap.set("n", "[f", function()
        step(-1)
    end, code)
end

local M = {}

function M.setup(manifest_path)
    local manifest = read_json(manifest_path)
    state.ws = manifest.workspace
    state.files = manifest.files
    if #state.files == 0 then
        error("review: manifest has no files")
    end

    vim.cmd("silent edit! " .. vim.fn.fnameescape(state.files[1].old))
    state.old_win = vim.api.nvim_get_current_win()

    vim.cmd("silent vsplit " .. vim.fn.fnameescape(state.files[1].path))
    state.new_win = vim.api.nvim_get_current_win()

    vim.cmd("silent vsplit " .. vim.fn.fnameescape(review_path()))
    state.review_win = vim.api.nvim_get_current_win()
    state.review_buf = vim.api.nvim_win_get_buf(state.review_win)

    vim.api.nvim_set_current_win(state.review_win)
    vim.wo[state.review_win].wrap = true
    vim.wo[state.review_win].linebreak = true
    vim.wo[state.review_win].winfixwidth = true
    vim.wo[state.review_win].number = false
    local width = math.max(40, math.floor(vim.o.columns * 0.35))
    vim.api.nvim_win_set_width(state.review_win, width)

    open_code(1)
    vim.api.nvim_set_current_win(state.review_win)

    setup_keys(state.review_buf)

    local group = vim.api.nvim_create_augroup("ReviewSession", { clear = true })
    vim.api.nvim_create_autocmd("VimLeavePre", {
        group = group,
        callback = write_comments,
    })
    vim.api.nvim_create_autocmd("TextChanged", {
        group = group,
        buffer = state.review_buf,
        callback = save_review,
    })
    vim.api.nvim_create_autocmd("InsertLeave", {
        group = group,
        buffer = state.review_buf,
        callback = save_review,
    })
end

function M.finish()
    save_review()
    write_comments()
    vim.cmd("silent! wall")
    vim.cmd("qa")
end

vim.api.nvim_create_user_command("ReviewDone", function()
    M.finish()
end, { desc = "Save the review notes and close the review window" })

vim.api.nvim_create_user_command("ReviewNext", function()
    step(1)
end, { desc = "Open the next reviewed file" })

vim.api.nvim_create_user_command("ReviewPrev", function()
    step(-1)
end, { desc = "Open the previous reviewed file" })

function _G.ReviewSetup(manifest_path)
    M.setup(manifest_path)
end
