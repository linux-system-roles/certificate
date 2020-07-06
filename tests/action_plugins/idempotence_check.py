# -*- coding: utf-8 -*-

from ansible import context
from ansible.executor.task_queue_manager import TaskQueueManager
from ansible.inventory.manager import InventoryManager
from ansible.module_utils.common.collections import ImmutableDict
from ansible.parsing.dataloader import DataLoader
from ansible.playbook.play import Play
from ansible.plugins.action import ActionBase
from ansible.vars.manager import VariableManager

STATS_NAMES = [
    "ok",
    "failures",
    "unreachable",
    "changed",
    "skipped",
    "rescued",
    "ignored",
]


def run_role(host, role_name, with_vars):

    loader = DataLoader()

    context.CLIARGS = ImmutableDict(
        connection="ssh",
        module_path=["~/.ansible/plugins/modules:/usr/share/ansible/plugins/modules"],
        forks=1,
        become=True,
        become_method="sudo",
        become_user="root",
        check=False,
        diff=False,
        verbosity=10,
    )

    sources = host + ","
    inventory = InventoryManager(loader=loader, sources=sources)

    variable_manager = VariableManager(loader=loader, inventory=inventory)

    play_source = dict(
        name="Ansible Play",
        hosts="all",
        gather_facts="yes",
        roles=[dict(name=role_name)],
    )

    try:
        play = Play().load(
            play_source,
            variable_manager=variable_manager,
            loader=loader,
            vars=with_vars,
        )
    except Exception as expt:
        print(expt)
        return None

    tqm = None
    try:
        tqm = TaskQueueManager(
            inventory=inventory,
            variable_manager=variable_manager,
            loader=loader,
            passwords=None,
        )
        result = tqm.run(play)
    finally:
        # we always need to cleanup child procs and the structures
        #   we use to communicate with them
        if tqm is not None:
            tqm.cleanup()

    if result != 0:
        return None

    return tqm._stats


class ActionModule(ActionBase):
    def run(self, tmp=None, task_vars=None):
        module_args = self._task.args.copy()
        role = module_args.get("role")
        with_vars = module_args.get("with_vars")
        host = task_vars.get("inventory_hostname")

        result = run_role(host, role, with_vars)

        stats = {}
        for stats_name in STATS_NAMES:
            state = getattr(result, stats_name, None)
            if state is not None:
                stats[stats_name] = sum([count for host, count in state.items()])

        if stats["changed"] or stats["failures"]:
            failed = True
            msg = "Idempotence check of role '{}' failed.".format(role)
        else:
            failed = False
            msg = "Idempotence check of role '{}' OK.".format(role)

        return dict(failed=failed, msg=msg, second_run_stats=stats)
