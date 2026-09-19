"""Reserved public-release update namespace. No network or package operations."""
REPOSITORY = "AAA404/fm10k-controlpanel-public"
UPDATE_MESSAGE = "OTA 入口已预留，待项目公开后接入 GitHub Releases。当前通过 Debian 安装包更新。"


def status(version):
    return {"enabled":False,"state":"reserved","current_version":version,
            "repository":REPOSITORY,"release_url":"https://github.com/"+REPOSITORY+"/releases",
            "message":UPDATE_MESSAGE,"component":"web"}
